package com.wangzan101.mika.cap.frida

import android.content.Context
import com.wangzan101.mika.core.cap.frida.FridaOutcome
import com.wangzan101.mika.core.cap.frida.FridaPort
import com.wangzan101.mika.core.cap.frida.FridaStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 内置 Frida:两个可执行文件随 APK 发布(jniLibs 里的 libfrida_server.so、libfrida_inject.so,arm64,
 * 安装时解到 nativeLibraryDir,和沙箱程序同一套机制),只在 arm64 的手机上可用。
 * 用之前经 su 复制到 /data/local/tmp/mika-frida(shell 可执行的上下文),frida-server 以 root 常驻,
 * frida-inject 每次注入起一个、跑完就退。所有 root 侧的事都经 [root](root 命令的端口)跑:
 * 用户没开「允许 Mika 执行 root 命令」时拿不到端口,工具不登记。
 */
/**
 * root 命令的最小端口:frida 不认识 root 能力(core 的依赖规矩,能力间不互引),
 * 调用方把 root 命令的端口(或别的以 root 跑命令的实现)适配成这个。
 */
fun interface RootRunner {
    suspend fun run(command: String, timeoutMs: Long): RootResult
}

/** 一次 root 命令的结局(frida 只认这几样;拒绝/没回话/不在都折成 Unavailable)。 */
sealed interface RootResult {
    data class Done(val exitCode: Int, val timedOut: Boolean, val stdout: String, val stderr: String, val droppedBytes: Long, val durationMs: Long) : RootResult
    data object NotRun : RootResult
}

class RootFrida(context: Context, private val root: RootRunner) : FridaPort {

    private val nativeDir = context.applicationInfo.nativeLibraryDir

    private fun bundled(bin: String) = File(nativeDir, "libfrida_$bin.so")

    private fun remote(bin: String) = "$REMOTE_DIR/$bin"

    // ---------- 状态 ----------

    override suspend fun status(): FridaStatus = withContext(Dispatchers.IO) {
        val have = bundled(SERVER).exists() && bundled(INJECT).exists()
        if (!have) return@withContext FridaStatus(serverRunning = false, installed = false, version = null, pid = null)
        val r = root.run(STATUS_SCRIPT, SHORT_MS)
        if (r !is RootResult.Done) return@withContext FridaStatus(serverRunning = false, installed = false, version = null, pid = null)
        val v = Regex("v='([^']*)'").find(r.stdout)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }
        val pid = Regex("pid='([0-9]+)'").find(r.stdout)?.groupValues?.get(1)?.toLongOrNull()
        val installed = Regex("installed='([01])'").find(r.stdout)?.groupValues?.get(1) == "1"
        FridaStatus(serverRunning = pid != null, installed = installed && v != null, version = v, pid = pid)
    }

    // ---------- 启动 / 停止 ----------

    override suspend fun start(force: Boolean): FridaOutcome = withContext(Dispatchers.IO) {
        if (!bundled(SERVER).exists()) return@withContext FridaOutcome.Unavailable(UNSUPPORTED)
        deploy()?.let { return@withContext it }
        val script = buildString {
            append("FORCE=${if (force) "1" else "0"}; ")
            append(PS_PIPELINE)
            append("if [ -n \"\$P\" ] && [ \"\$FORCE\" = \"1\" ]; then kill -9 \"\$P\" 2>/dev/null; sleep 1; P=; fi; ")
            append("if [ -z \"\$P\" ]; then ")
            append("nohup ${remote(SERVER)} >$REMOTE_DIR/server.log 2>&1 & sleep 1; ")
            append(PS_PIPELINE)
            append("if [ -n \"\$P\" ]; then echo RUNNING; else echo NOT_RUNNING; fi; ")
            append("else echo ALREADY_RUNNING; fi")
        }
        finish(root.run(script, START_MS))
    }

    override suspend fun stop(): FridaOutcome = withContext(Dispatchers.IO) {
        val script = "pkill -f '$REMOTE_DIR/${SERVER}' 2>/dev/null; sleep 1; " +
            "ps -A -o ARGS 2>/dev/null | grep -F '$REMOTE_DIR/${SERVER}' | grep -v grep >/dev/null && echo STILL_RUNNING || echo STOPPED"
        finish(root.run(script, SHORT_MS))
    }

    // ---------- 注入 ----------

    override suspend fun inject(target: String, script: String, timeoutSec: Int): FridaOutcome = withContext(Dispatchers.IO) {
        if (!bundled(INJECT).exists()) return@withContext FridaOutcome.Unavailable(UNSUPPORTED)
        deploy()?.let { return@withContext it }
        // 脚本编成 base64 塞进命令(root 命令本来就经 base64 传,再包一层),frida-inject 跑完就结束
        val b64 = android.util.Base64.encodeToString(script.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
        val t = target.trim()
        val attach = if (t.matches(Regex("[0-9]+"))) "-p $t" else "-n '$t'"
        val cmd = "S=$REMOTE_DIR/script.last; echo $b64 | base64 -d > \"\$S\"; ${remote(INJECT)} $attach -s \"\$S\"; RC=\$?; rm -f \"\$S\"; exit \$RC"
        finish(root.run(cmd, timeoutSec * 1000L + GRACE_MS))
    }

    // ---------- 部署 ----------

    /** 都在位时返回 null;否则返回一次失败的 [FridaOutcome]。 */
    private suspend fun deploy(): FridaOutcome? {
        val srcServer = bundled(SERVER).path
        val srcInject = bundled(INJECT).path
        val cmd = "mkdir -p $REMOTE_DIR && " +
            "cp -f '$srcServer' ${remote(SERVER)} && cp -f '$srcInject' ${remote(INJECT)} && " +
            "chmod 755 ${remote(SERVER)} ${remote(INJECT)} && echo DEPLOY_OK"
        val r = root.run(cmd, DEPLOY_MS)
        if (r is RootResult.Done && "DEPLOY_OK" in r.stdout) return null
        return FridaOutcome.Unavailable(
            when (r) {
                is RootResult.Done -> "Deploying Frida failed: ${(r.stderr.ifBlank { r.stdout }).take(200)}"
                RootResult.NotRun -> "su refused, did not answer, or is gone; Frida binaries were not deployed."
            },
        )
    }

    /** 把一次 RootResult 折成 FridaOutcome。 */
    private fun finish(r: RootResult): FridaOutcome = when (r) {
        is RootResult.Done -> FridaOutcome.Done(
            ok = r.exitCode == 0 && !r.timedOut, exitCode = r.exitCode, timedOut = r.timedOut, durationMs = r.durationMs,
            stdout = r.stdout, stderr = r.stderr, droppedBytes = r.droppedBytes,
        )
        RootResult.NotRun -> FridaOutcome.Unavailable("su refused, did not answer, or is gone.")
    }

    companion object {
        const val SERVER = "server"
        const val INJECT = "inject"
        const val REMOTE_DIR = "/data/local/tmp/mika-frida"
        private const val SHORT_MS = 15_000L
        private const val START_MS = 30_000L
        private const val DEPLOY_MS = 120_000L
        private const val GRACE_MS = 5_000L
        private const val UNSUPPORTED = "Frida ships for arm64 phones only; this device has no bundled Frida binaries."

        private fun remote(bin: String) = "$REMOTE_DIR/$bin"

        /** 找 frida-server 进程:ps 的 ARGS 里带部署路径的才算,拿到它的 pid。 */
        private val PS_PIPELINE =
            "P=\$(ps -A -o PID,ARGS 2>/dev/null | grep -F '$REMOTE_DIR/${SERVER}' | grep -v grep | head -n 1 | sed 's/^ *//;s/[^0-9].*//'); "

        /** 一次看全:装没装、版本、在跑的 pid。 */
        private val STATUS_SCRIPT =
            "V=\$(${remote(SERVER)} --version 2>/dev/null); I=0; [ -x ${remote(SERVER)} ] && [ -x ${remote(INJECT)} ] && I=1; " + PS_PIPELINE +
                "echo \"v='\$V' pid='\$P' installed='\$I'\""
    }
}
