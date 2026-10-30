# -*- coding: utf-8 -*-
"""开源前泄漏检查: 机器相关路径 / 个人信息 / 缓存残留"""
import pathlib
import re

PATTERNS = [
    ("本机用户名示例", "40" + "928"),   # 拼接写法, 避免脚本自身被误报
    ("绝对用户目录", "C:" + chr(92) + "Users"),
    ("rockyou 绝对路径", "D:" + chr(92) + "rockyou"),
    ("JtR 绝对路径", "D:" + chr(92) + "John"),
    ("工作区路径", "Desktop" + chr(92) + "测试项目"),
]
SKIP_DIRS = {"预编译", ".git"}

hits = []
for p in pathlib.Path(".").rglob("*"):
    if not p.is_file():
        continue
    if any(s in p.parts for s in SKIP_DIRS):
        continue
    if p.suffix.lower() not in {".py", ".md", ".txt", ".json", ".yml", ".yaml",
                                ".spec", ".bat", ".cfg", ".toml"}:
        continue
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        continue
    for label, pat in PATTERNS:
        if pat in text:
            hits.append(f"{p}  ← {label}")

print("泄漏检查:", "通过 (无命中)" if not hits else "发现 %d 处" % len(hits))
for h in hits:
    print("  -", h)

print("__pycache__ 残留:", any("__pycache__" in str(x) for x in pathlib.Path(".").rglob("*")))
print("instances/ 存在:", pathlib.Path("instances").exists())
print("dist/ 存在:", pathlib.Path("dist").exists())
print("resources 缓存存在:", pathlib.Path("lib/resources.json").exists())
