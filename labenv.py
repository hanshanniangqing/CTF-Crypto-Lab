# -*- coding: utf-8 -*-
"""
labenv.py — 运行环境定位 (源码运行 / PyInstaller 打包运行 通用)

* LAB  : 只读资源根 (challenges/, lib/, tools/)  —— 打包后即 exe 所在目录
* WLAB : 可写根 (dist/, instances/, lib/resources.json 缓存)
         若 exe 目录不可写 (如 Program Files), 自动回退到
         %LOCALAPPDATA%\\CTF-Crypto-Lab (Windows) / ~/.ctf-crypto-lab
"""
import os
import sys
from pathlib import Path


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def writable_root() -> Path:
    root = app_root()
    try:
        probe = root / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return root
    except OSError:
        if os.name == "nt":
            base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CTF-Crypto-Lab"
        else:
            base = Path.home() / ".ctf-crypto-lab"
        base.mkdir(parents=True, exist_ok=True)
        return base


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


LAB = app_root()
WLAB = writable_root()

# 打包运行时把内置 lib 挂到 sys.path, 供 solve.py / server.py 直接 import ctfk
_LIB = LAB / "lib"
if _LIB.is_dir() and str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))
