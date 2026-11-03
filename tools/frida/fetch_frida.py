#!/usr/bin/env python3
"""下载内置 Frida 的两个二进制(frida-server、frida-inject,android-arm64),解压并按 jniLibs 命名放好。

产物:app/src/main/jniLibs/arm64-v8a/libfrida_server.so、libfrida_inject.so。
版本与 SHA-256 钉在这里;升级版本时改 FRIDA_VERSION 并核对两个哈希。
"""
import hashlib
import lzma
import pathlib
import shutil
import sys
import urllib.request

FRIDA_VERSION = "17.25.2"
ASSETS = {
    "frida-server": "frida-server-{v}-android-arm64.xz",
    "frida-inject": "frida-inject-{v}-android-arm64.xz",
}
# 上游发布包的 SHA-256(xz 压缩包);对不上就退出,免得把不认识的二进制打进 APK。
SHA256 = {
    "frida-server": "08d7b7f02256621c9089cecd6495a5eb43861bf560a7ed86ad376e75d16a1fb6",
    "frida-inject": "5c9210e6fc0c2f9f0ce53d8a794ea5efff07f42d1a72a4a47d5d362e1d10cbfa",
}
BASE = "https://github.com/frida/frida/releases/download"

root = pathlib.Path(__file__).resolve().parents[2]
out_dir = root / "app/src/main/jniLibs/arm64-v8a"


def fetch(name: str, template: str) -> bytes:
    url = f"{BASE}/{FRIDA_VERSION}/{template.format(v=FRIDA_VERSION)}"
    for attempt in range(5):
        try:
            print(f"GET {url} (attempt {attempt + 1})")
            req = urllib.request.Request(url, headers={"User-Agent": "mika-build"})
            chunks = []
            with urllib.request.urlopen(req, timeout=300) as r:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    chunks.append(b)
            return b"".join(chunks)
        except Exception as e:  # 网络抖动重试
            print(f"  failed: {e}", file=sys.stderr)
    raise SystemExit(f"could not download {url}")


def main() -> int:
    print_mode = "--print" in sys.argv
    for name, template in ASSETS.items():
        data = fetch(name, template)
        sha = hashlib.sha256(data).hexdigest()
        print(f"{name}: sha256={sha} size={len(data)}")
        if print_mode:
            continue
        expected = SHA256.get(name, "0")
        if expected != "0" and expected != sha:
            print(f"{name}: sha256 mismatch (expected {expected})", file=sys.stderr)
            return 1
        raw = lzma.decompress(data)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"libfrida_{name.split('-')[1]}.so"
        out.write_bytes(raw)
        out.chmod(0o755)
        print(f"wrote {out} ({len(raw)} bytes)")
    if print_mode:
        print("Copy the sha256 values above into tools/frida/fetch_frida.py and rerun without --print.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
