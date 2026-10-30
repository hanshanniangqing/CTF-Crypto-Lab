# -*- coding: utf-8 -*-
"""
build_common.py — 出题脚本公共设施

所有 tools/build_*.py 出题脚本 import 本模块:
    from build_common import *

一个出题脚本的结构:
    from build_common import *

    BUILDERS = {}

    @register("rsa-baby")
    def gen_rsa_baby(ch):
        rng = rng_for("rsa-baby")
        ... 计算材料 ...
        write_src("rsa-baby", "output.txt", "...")
        verify("rsa-baby", 条件, "自检说明")

    if __name__ == "__main__":
        run_builders(BUILDERS)
"""
import importlib
import json
import os
import random
import sys
import zlib
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "lib"))
import ctfk  # noqa: E402  (共用密码学工具箱)

INDEX_PATH = LAB / "challenges" / "index.json"

_failures = []


def load_index():
    with open(INDEX_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {c["name"]: c for c in data["challenges"]}


_INDEX = load_index()


def entry(name):
    return _INDEX[name]


def ch_dir(name):
    c = _INDEX[name]
    return LAB / "challenges" / c["category"] / c["name"]


def src_dir(name):
    d = ch_dir(name) / "src"
    d.mkdir(parents=True, exist_ok=True)
    return d


def rng_for(name):
    """确定性随机源 (跨平台一致, 与运行顺序无关)"""
    return random.Random(zlib.crc32(name.encode()) ^ 0x20261025)


def write_src(name, filename, data):
    """写入题目附件 (str 按 utf-8 文本写, bytes 按二进制写)"""
    p = src_dir(name) / filename
    if isinstance(data, bytes):
        p.write_bytes(data)
    else:
        p.write_text(data, encoding="utf-8")
    return p


def write_solution(name, filename, text):
    d = ch_dir(name) / "solution"
    d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    p.write_text(text, encoding="utf-8")
    return p


def verify(name, cond, msg):
    """出题自检; 失败会被 run_builders 汇总报告"""
    if not cond:
        _failures.append(f"{name}: {msg}")
        print(f"  [SELF-FAIL] {name}: {msg}")
    return cond


def register(name):
    def deco(fn):
        BUILDERS[name] = fn
        return fn
    return deco


BUILDERS = {}


def run_builders(builders):
    only = os.environ.get("CTF_REGEN_ONLY", "")
    only_set = {s.strip() for s in only.split(",") if s.strip()} if only else None
    for name, fn in builders.items():
        if only_set is not None and name not in only_set:
            continue
        try:
            fn(_INDEX[name])
            print(f"[build] {name}: OK")
        except Exception as e:
            _failures.append(f"{name}: EXCEPTION {type(e).__name__}: {e}")
            import traceback
            print(f"[build] {name}: EXCEPTION\n{traceback.format_exc()}")
    if _failures:
        print(f"\n=== BUILD FAILURES ({len(_failures)}) ===")
        for f in _failures:
            print(" -", f)
        sys.exit(1)
    print("build done")
