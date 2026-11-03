package com.wangzan101.mika.core.cap.frida

/**
 * 内置 Frida 的端口:core 只认这个接口;app 侧实现(经 su 跑 frida-server / frida-inject)。
 * 用户打开「允许 Mika 执行 root 命令」才由 App 给出,否则不给(工具不登记)。
 */
interface FridaPort {
    /** 看状态:frida-server 是否在跑(按进程表)、二进制装没装、版本。 */
    suspend fun status(): FridaStatus

    /**
     * 启动 frida-server(需要时先部署二进制)。已在跑时直接成功。
     * [force]:先停掉已在跑的实例再起一个新的。
     */
    suspend fun start(force: Boolean): FridaOutcome

    /** 停止 frida-server。没在跑也算成功。 */
    suspend fun stop(): FridaOutcome

    /**
     * 用 frida-inject 往目标进程注一次脚本:[target] 是进程名或 PID,[script] 是 JavaScript 源码
     * (frida-inject 跑完脚本被杀或目标退出后返回)。永久驻留(eternalize)不支持。
     */
    suspend fun inject(target: String, script: String, timeoutSec: Int): FridaOutcome
}

/** frida 的可见状态(工具结果与设置里显示)。 */
data class FridaStatus(
    val serverRunning: Boolean,
    /** 二进制已部署到 /data/local/tmp:第一次用之前是 false。 */
    val installed: Boolean,
    val version: String?,
    /** server 进程里看到的 pid;没在跑为 null。 */
    val pid: Long?,
)

/** 一次 frida 操作的结局。 */
sealed interface FridaOutcome {
    /** 跑了。[stdout]、[stderr] 各最多留 1 MB,多的丢掉并计入 [droppedBytes]。 */
    data class Done(
        val ok: Boolean, val exitCode: Int, val timedOut: Boolean, val durationMs: Long,
        val stdout: String, val stderr: String, val droppedBytes: Long,
    ) : FridaOutcome

    /** su 拒绝了、没回话或 su 不在了(见 message)。 */
    data class Unavailable(val reason: String) : FridaOutcome
}
