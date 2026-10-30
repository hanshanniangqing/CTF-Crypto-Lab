"""题解：affine-brute
## 漏洞点
仿射密码 c = a*p + b (mod 26) 的密钥空间极小: a 必须与 26 互素 (12 个
取值), b 任意 (26 个取值), 总共只有 12*26=312 个密钥。逐个解密并用英文
频率评分, 立刻就能挑出正确密钥。

## 利用思路
1. 枚举全部合法密钥: a in {1,3,5,7,9,11,15,17,19,21,23,25}, b in 0..25。
2. 对每个 (a, b) 用 ctfk.affine_decrypt 解密候选明文。
3. 用 ctfk.chi2_english 评分, 卡方偏差最小的候选即真实明文。
4. 正则提取 flag{...}。

## 关键代码
best = min((ctfk.chi2_english(ctfk.affine_decrypt(text, a, b)), a, b)
           for a in COPRIMES for b in range(26))
plain = ctfk.affine_decrypt(text, best[1], best[2])

## 防御建议
- 312 个密钥连现代计算机的毫秒级算力都消耗不掉, 密钥空间必须足够大。
- 即使扩大模数, 仿射结构 (线性变换) 仍易被已知明文/频率分析攻破。
- 现代场景使用标准对称加密; 古典密码仅用于理解密码分析思想。
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk

COPRIMES = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)


def main():
    text = open("cipher.txt", encoding="utf-8").read()
    best = min((ctfk.chi2_english(ctfk.affine_decrypt(text, a, b)), a, b)
               for a in COPRIMES for b in range(26))
    plain = ctfk.affine_decrypt(text, best[1], best[2])
    m = re.search(r"flag\{[^}]*\}", plain)
    assert m, "爆破最优解密结果中未找到 flag"
    print(m.group(0))


if __name__ == "__main__":
    main()
