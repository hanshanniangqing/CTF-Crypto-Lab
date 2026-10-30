# -*- coding: utf-8 -*-
"""从各题 solution/solve.py 的模块 docstring 提取生成 solution/writeup.md"""
import ast
import json
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]


def main():
    index = json.loads((LAB / "challenges" / "index.json").read_text(encoding="utf-8"))
    made = 0
    for ch in index["challenges"]:
        solve = LAB / "challenges" / ch["category"] / ch["name"] / "solution" / "solve.py"
        if not solve.exists():
            continue
        try:
            tree = ast.parse(solve.read_text(encoding="utf-8"))
            doc = ast.get_docstring(tree) or ""
        except SyntaxError as e:
            print(f"[skip] {ch['name']}: syntax error {e}")
            continue
        if not doc.strip():
            print(f"[skip] {ch['name']}: empty docstring")
            continue
        header = (
            f"# {ch['name']} — 题解\n\n"
            f"> {ch['category']} / {ch['difficulty']} / {ch['points']} 分 / 考点: {ch['technique']}\n\n"
        )
        out = LAB / "challenges" / ch["category"] / ch["name"] / "solution" / "writeup.md"
        lines = doc.strip().splitlines()
        # 去掉与页眉重复的 "题解：题目名" 首行
        while lines and (lines[0].strip().startswith(("题解", "# ")) or not lines[0].strip()):
            lines.pop(0)
        out.write_text(header + "\n".join(lines).strip() + "\n", encoding="utf-8")
        made += 1
    print(f"writeups generated: {made}")


if __name__ == "__main__":
    main()
