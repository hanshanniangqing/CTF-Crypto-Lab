#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_release.py — 一键生成免安装发行版 (Windows)

    python scripts/build_release.py

产物:
    build_dist/CTF-Crypto-Lab/           可直接双击运行的目录
    release/CTF-Crypto-Lab-v<版本>-win64.zip   分发包

依赖: pip install pyinstaller pycryptodome rich sympy
"""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "build_dist" / "CTF-Crypto-Lab"
ZIP_DIR = ROOT / "release"

LAUNCHER_SITE = (
    "@echo off\r\n"
    "chcp 65001 >nul\r\n"
    'cd /d "%~dp0"\r\n'
    "echo 正在启动 CTF Crypto Lab 题目站...\r\n"
    "CTF-Crypto-Lab.exe\r\n"
)
LAUNCHER_TOOLKIT = (
    "@echo off\r\n"
    "chcp 65001 >nul\r\n"
    'cd /d "%~dp0"\r\n'
    "echo 正在启动密码工具箱...\r\n"
    "CTF-Crypto-Lab.exe toolkit\r\n"
)


def version() -> str:
    for line in (ROOT / "ctf.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION"):
            return line.split('"')[1].split()[-1]
    return "dev"


def sh(cmd):
    print("+", " ".join(str(x) for x in cmd))
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        raise SystemExit(f"命令失败: {cmd}")


def main():
    if sys.platform != "win32":
        print("提示: 本项目以 Windows 免安装版为主要分发形式, 其他平台请从源码运行。")

    ver = version()
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    shutil.rmtree(ROOT / "build_dist", ignore_errors=True)
    sh([sys.executable, "-m", "PyInstaller", "ctf_crypto_lab.spec",
        "--noconfirm", "--distpath", "build_dist", "--workpath", "build"])

    # 发行版附加文件
    readme = ROOT / "docs" / "使用说明.txt"
    if readme.exists():
        shutil.copy2(readme, DIST / "使用说明.txt")
    (DIST / "启动题目站.bat").write_text(LAUNCHER_SITE, encoding="utf-8", newline="")
    (DIST / "启动工具箱.bat").write_text(LAUNCHER_TOOLKIT, encoding="utf-8", newline="")
    shutil.copy2(ROOT / "LICENSE", DIST / "LICENSE")

    # 清理运行时残留
    for junk in ("dist", "instances", "lib/resources.json"):
        p = DIST / junk
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()

    # 打包 zip
    ZIP_DIR.mkdir(exist_ok=True)
    out = ZIP_DIR / f"CTF-Crypto-Lab-v{ver}-win64.zip"
    if out.exists():
        out.unlink()
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in DIST.rglob("*"):
            if p.is_file():
                z.write(p, (Path("CTF-Crypto-Lab") / p.relative_to(DIST)).as_posix())
                n += 1
    print(f"\n完成: {n} 个文件")
    print(f"  目录: {DIST}")
    print(f"  压缩包: {out} ({out.stat().st_size / 1048576:.1f} MB)")


if __name__ == "__main__":
    main()
