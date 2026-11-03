# 内置 Frida

App 带两个 Frida 可执行文件(frida-server、frida-inject,android-arm64),经
`tools/frida/fetch_frida.py` 从 Frida 官方发布下载、核对 SHA-256 后放到
`app/src/main/jniLibs/arm64-v8a/libfrida_server.so`、`libfrida_inject.so`,
随 APK 安装到 `nativeLibraryDir`(和沙箱的 proot 一套机制,安装时解到磁盘)。

用的时候(`app/.../cap/frida/RootFrida.kt`)经 root 命令把它们复制到
`/data/local/tmp/mika-frida/` 再执行:frida-server 以 root 常驻,frida-inject
每次注入起一个、跑完就退。用户没打开「允许 Mika 执行 root 命令」时 Frida 工具不登记。

## 重现

```bash
python3 tools/frida/fetch_frida.py --print   # 只打印版本与 SHA-256
python3 tools/frida/fetch_frida.py           # 下载、核对、放到 jniLibs
```

版本与哈希钉在脚本里;升级版本时改 `FRIDA_VERSION`,用 `--print` 取新哈希填回 `SHA256`。

| 文件 | 来源 | 许可证 |
|---|---|---|
| `libfrida_server.so` | frida releases(frida-server) | Frida 自定义许可(见 licenses/THIRD_PARTY_NOTICES.md) |
| `libfrida_inject.so` | frida releases(frida-inject) | 同上 |
