# -*- coding: utf-8 -*-
"""从 challenges/index.json 生成 README.md 中的题目总表 (替换 <!-- TABLE --> 标记)"""
import json
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]

CAT_CN = {
    "classical": "古典密码",
    "symmetric": "对称密码",
    "stream": "流密码与PRNG",
    "rsa": "RSA",
    "pubkey": "公钥与离散对数",
    "hash": "哈希",
    "lattice": "格密码",
    "cracking": "口令破解实战",
}
ORDER = ["classical", "symmetric", "stream", "rsa", "pubkey", "hash", "lattice", "cracking"]


def main():
    index = json.loads((LAB / "challenges" / "index.json").read_text(encoding="utf-8"))["challenges"]
    lines = ["| # | 题目 | 分类 | 难度 | 分值 | 考点 |",
             "|---|------|------|------|------|------|"]
    for i, ch in enumerate(sorted(index, key=lambda c: (ORDER.index(c["category"]), c["points"])), 1):
        lines.append(f"| {i} | `{ch['name']}` | {CAT_CN[ch['category']]} | {ch['difficulty']} "
                     f"| {ch['points']} | {ch['technique']} |")
    table = "\n".join(lines)

    readme = LAB / "README.md"
    text = readme.read_text(encoding="utf-8")
    if "<!-- TABLE -->" in text:
        text = text.replace("<!-- TABLE -->", table, 1)
        readme.write_text(text, encoding="utf-8")
        print("table inserted")
    else:
        # 已插入过 → 替换旧表 (从表头到表尾)
        import re
        text = re.sub(r"\| # \| 题目 \| 分类 \| 难度 \| 分值 \| 考点 \|\n(\|[-| ]+\n\|[^\n]*\n?)+", table, text)
        readme.write_text(text, encoding="utf-8")
        print("table replaced")


if __name__ == "__main__":
    main()
