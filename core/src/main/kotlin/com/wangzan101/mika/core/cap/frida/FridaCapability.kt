package com.wangzan101.mika.core.cap.frida

import com.wangzan101.mika.core.capability.Capability
import com.wangzan101.mika.core.capability.CapabilityKey
import com.wangzan101.mika.core.capability.CapabilityStatus
import com.wangzan101.mika.core.capability.PromptEnv
import com.wangzan101.mika.core.prompt.Prompts
import com.wangzan101.mika.core.tool.AgentTool
import com.wangzan101.mika.core.tool.ToolContext

/**
 * 内置 Frida:经 root 跑随包发布的 frida-server / frida-inject。只有用户打开了「允许 Mika 执行 root 命令」、
 * App 给了端口才装上(工具才登记);不动屏幕,只有一个工具。
 * 会改动东西的调用(start、inject)询问时先问用户(工具按参数申报,见 [FridaTool.approvalRisk])。
 */
internal class FridaCapability(val port: FridaPort) : Capability {
    override val id = FRIDA

    override fun status(): CapabilityStatus = CapabilityStatus.Available

    override fun tools(): List<AgentTool> = FridaGroup.tools

    override fun sections(env: PromptEnv): List<String> =
        if (FridaGroup.tools.any { it.name in env.offered }) listOf(env.gate(Prompts.capability(FRIDA))) else emptyList()

    override fun onTaskStart(ctx: ToolContext) {
        ctx[KEY] = this
    }

    companion object {
        val KEY = CapabilityKey<FridaCapability>(FRIDA)
    }
}

internal val ToolContext.fridaPort: FridaPort? get() = this[FridaCapability.KEY]?.port
