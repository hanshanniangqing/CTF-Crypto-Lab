r"""题解：caesar-rot
## 漏洞点
凯撒密码的密钥空间只有 26 (有效移位 25), 且不改变字母频率分布: 加密后
字母只是整体平移, e 仍是最高频字母。对每一段足够长的英文密文, 频率统计
足以唯一确定移位量。

## 利用思路
1. 读入 cipher.txt。
2. 对 k = 0..25 的每个移位, 用 ctfk.caesar_shift(text, -k) 解出候选明文。
3. 用 ctfk.chi2_english 计算候选明文与英文频率的卡方偏差, 偏差最小的
   即正确移位。
4. 在解出的明文中用正则提取 flag{...}。

## 关键代码
best = min(range(26), key=lambda k: ctfk.chi2_english(
    ctfk.caesar_shift(text, -k)))
plain = ctfk.caesar_shift(text, -best)
flag = re.search(r"flag\{[^}]*\}", plain).group(0)

## 防御建议
- 移位密码密钥空间太小, 任何长度的英文消息都应视为可被频率分析秒破。
- 至少升级为带长密钥的多表密码 (如维吉尼亚), 但它同样有统计攻击。
- 现代场景应直接使用 AES/ChaCha20 等标准算法, 古典密码仅作教学用途。
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    text = open("cipher.txt", encoding="utf-8").read()
    best = min(range(26),
               key=lambda k: ctfk.chi2_english(ctfk.caesar_shift(text, -k)))
    plain = ctfk.caesar_shift(text, -best)
    m = re.search(r"flag\{[^}]*\}", plain)
    assert m, "卡方最优解密结果中未找到 flag"
    print(m.group(0))


if __name__ == "__main__":
    main()
