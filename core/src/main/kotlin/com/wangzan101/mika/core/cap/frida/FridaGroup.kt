package com.wangzan101.mika.core.cap.frida

import com.wangzan101.mika.core.action.Risk as ApprovalRisk
import com.wangzan101.mika.core.gate.ConfirmationRequest
import com.wangzan101.mika.core.risk.IrrevAction
import com.wangzan101.mika.core.observation.ObsKind
import com.wangzan101.mika.core.observation.Observation
import com.wangzan101.mika.core.observation.Place
import com.wangzan101.mika.core.observation.Trust
import com.wangzan101.mika.core.observation.Untrusted
import com.wangzan101.mika.core.prompt.Prompts
import com.wangzan101.mika.core.tool.AgentTool
import com.wangzan101.mika.core.tool.Args
import com.wangzan101.mika.core.tool.OutputClip
import com.wangzan101.mika.core.tool.Risk
import com.wangzan101.mika.core.tool.ToolContext
import com.wangzan101.mika.core.tool.ToolDef
import com.wangzan101.mika.core.tool.ToolExecution
import com.wangzan101.mika.core.tool.Verb
import com.wangzan101.mika.core.tool.argStr
import com.wangzan101.mika.core.tool.int
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

internal const val FRIDA = "frida"

private const val SCRIPT_MAX = 200_000
private const val DEFAULT_TIMEOUT_SEC = 30
private const val MAX_TIMEOUT_SEC = 600

/**
 * 内置 Frida:一个工具管状态、起停与注入。脚本经 frida-inject 以 root 跑,别的 App 感觉不到来源。
 * 不动屏幕,进动作清单;注入脚本要用户同意(工具按参数申报,见 [FridaTool.approvalRisk])。
 */
internal object FridaTool : AgentTool {
    override val capability: String get() = FRIDA
    override val verb = Verb.RootCommand
    override val label = "Frida"
    override val risk = Risk.Write
    override val offScreen = true
    override val logged = true
    override val wideTarget = true
    override val def = ToolDef("frida_run", Prompts.tool("frida_run"), mapOf(
        "action" to buildJsonObject {
            put("type", "string")
            put("description", "status: check the bundled Frida (server running? binary deployed?). start: start frida-server as root (set force to restart it). stop: stop frida-server. inject: attach to a process and run a JavaScript script once.")
            put("enum", kotlinx.serialization.json.JsonArray(listOf("status", "start", "stop", "inject").map(::JsonPrimitive)))
        },
        "target" to buildJsonObject {
            put("type", "string")
            put("description", "inject only: process name (e.g. com.example.app) or numeric PID to attach to.")
        },
        "script" to buildJsonObject {
            put("type", "string")
            put("description", "inject only: Frida JavaScript source (1-$SCRIPT_MAX characters). Runs once in the target process; its console.log output comes back in stdout.")
            put("minLength", 1); put("maxLength", SCRIPT_MAX)
        },
        "force" to buildJsonObject { put("type", "boolean"); put("description", "start only: stop a running server first, then start a fresh one. Default false.") },
        "timeoutSec" to int("inject only: time limit in seconds, 1-$MAX_TIMEOUT_SEC (default $DEFAULT_TIMEOUT_SEC). The inject run is stopped when it runs out.", 1, MAX_TIMEOUT_SEC),
    ), listOf("action"))

    override fun available(ctx: ToolContext) = ctx.fridaPort != null

    /** status / stop 直接做;start 与 inject 是不在屏上、改了收不回的一步,申报就是它自己。 */
    override fun approvalRisk(args: JsonObject) = when ((args["action"] as? JsonPrimitive)?.contentOrNull) {
        "start", "inject" -> ApprovalRisk(
            com.wangzan101.mika.core.action.ActionRisk.Irreversible,
            ask = ConfirmationRequest(IrrevAction.other, "", describe(args), null, FRIDA),
        )
        else -> null
    }

    private fun describe(args: JsonObject): String = when (val a = (args["action"] as? JsonPrimitive)?.contentOrNull) {
        "start" -> "frida-server start" + if ((args["force"] as? JsonPrimitive)?.content == "true") " (force)" else ""
        "inject" -> "frida inject ${args["target"]?.toString()?.take(200)}"
        else -> a ?: "frida"
    }

    override suspend fun execute(a: Args, ctx: ToolContext): ToolExecution {
        val port = ctx.fridaPort!!
        return when (a.str("action")!!) {
            "status" -> {
                val s = port.status()
                ToolExecution(buildJsonObject {
                    put("ok", true)
                    put("serverRunning", s.serverRunning)
                    put("installed", s.installed)
                    s.version?.let { put("version", it) }
                    s.pid?.let { put("pid", it) }
                    if (!s.installed) put("note", "The Frida binaries deploy to /data/local/tmp on first use; call start first.")
                })
            }
            "start" -> done(port.start(a.bool("force", default = false)), "frida-server start")
            "stop" -> done(port.stop(), "frida-server stop")
            "inject" -> {
                val target = a.str("target", max = 200)
                val script = a.str("script", max = SCRIPT_MAX)
                if (target == null || script == null) return fail("frida_args", "inject needs target (process name or PID) and script.")
                done(port.inject(target, script, a.int("timeoutSec", 1, MAX_TIMEOUT_SEC) ?: DEFAULT_TIMEOUT_SEC), "frida inject $target")
            }
            else -> fail("frida_action", "Unknown action.")
        }
    }

    private fun done(r: FridaOutcome, command: String): ToolExecution = when (r) {
        is FridaOutcome.Done -> {
            val (out, outClipped) = OutputClip.clip(r.stdout)
            val (err, errClipped) = OutputClip.clip(r.stderr, head = 1_000, tail = 3_000)
            val hints = listOfNotNull(
                com.wangzan101.mika.core.prompt.Feedback["frida.timed_out"].takeIf { r.timedOut },
                com.wangzan101.mika.core.prompt.Feedback["frida.truncated"].takeIf { outClipped || errClipped || r.droppedBytes > 0 },
            )
            ToolExecution(buildJsonObject {
                put("ok", r.ok && !r.timedOut); put("exitCode", r.exitCode); put("timedOut", r.timedOut); put("durationMs", r.durationMs)
                put("stdout", Untrusted.wrap(out)); put("stderr", Untrusted.wrap(err))
                if (r.droppedBytes > 0) put("droppedBytes", r.droppedBytes)
                if (hints.isNotEmpty()) put("hint", hints.joinToString(" "))
            }, observations = listOf(Observation(ObsKind.Output, "退出码 ${r.exitCode}:\n$out", source = FRIDA,
                place = Place.command("「${command.take(200)}」"), trust = Trust.Untrusted, authored = command)))
        }
        is FridaOutcome.Unavailable -> fail("frida_unavailable", r.reason)
    }

    private fun fail(error: String, message: String) = ToolExecution(buildJsonObject {
        put("ok", false); put("error", error); put("message", message); put("recoverable", false)
    })

    override fun logTarget(o: JsonObject, r: ToolExecution, ctx: ToolContext) = o.argStr("action")?.let { act ->
        val t = o.argStr("target")
        if (t == null) "frida $act" else "frida $act $t"
    }
}

internal object FridaGroup {
    val tools: List<AgentTool> = listOf(FridaTool)
}
