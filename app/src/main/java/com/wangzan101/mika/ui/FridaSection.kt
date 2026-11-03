package com.wangzan101.mika.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import com.wangzan101.mika.cap.phone.PhoneServices
import com.wangzan101.mika.ui.components.FooterNote
import com.wangzan101.mika.ui.components.GroupCard
import com.wangzan101.mika.ui.components.GroupLabel
import com.wangzan101.mika.ui.components.ListRow
import com.wangzan101.mika.ui.components.RowValue
import com.wangzan101.mika.ui.components.TileTone
import com.wangzan101.mika.ui.components.ValueTone
import com.wangzan101.mika.ui.theme.MikaIcons

/**
 * 设置 › 手机操作里「内置 Frida」那一组:只在找得到 su 的手机上显示（本身不另设开关）——
 * 能不能用跟着「允许 Mika 执行 root 命令」走。这一行是纯状态:打开 root 命令那组即用。
 */
@Composable
fun FridaSection() {
    val context = LocalContext.current
    val root = remember { PhoneServices.of(context).shellManager.root }
    val state by root.state.collectAsState()
    if (!state.suPresent) return
    FridaSectionView(commandsOn = state.commands)
}

@Composable
fun FridaSectionView(commandsOn: Boolean) {
    GroupLabel(PhoneSetupCopy.FRIDA_GROUP)
    GroupCard {
        ListRow(
            MikaIcons.Bug, PhoneSetupCopy.FRIDA_ROW,
            if (commandsOn) PhoneSetupCopy.FRIDA_ROW_SUB_ON else PhoneSetupCopy.FRIDA_ROW_SUB_OFF, first = true,
            tone = if (commandsOn) TileTone.Neutral else TileTone.Neutral,
        ) { RowValue(if (commandsOn) "on" else "off", if (commandsOn) ValueTone.Ok else ValueTone.Plain) }
    }
    FooterNote(PhoneSetupCopy.FRIDA_NOTE)
}
