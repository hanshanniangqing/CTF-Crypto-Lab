"""题解：rsa-common-modulus
## 漏洞点
同一条消息 m 用同一个模数 n、两个互素的指数 e1, e2 加密并公开。由于
gcd(e1, e2) = 1，存在整数 s1, s2 使 s1*e1 + s2*e2 = 1。攻击者无需知道
任何私钥即可恢复明文——RSA 在共模场景下完全失去安全性。

## 利用思路
1. 对 (e1, e2) 跑扩展欧几里得得到 (g, s1, s2)，g=1 时 s1*e1 + s2*e2 = 1。
2. 计算 c1^s1 * c2^s2 mod n = m^(s1*e1 + s2*e2) = m^1 = m。
3. 负指数用模逆等价处理 (Python 的 pow 支持负指数)。

## 关键代码
g, s1, s2 = egcd(e1, e2)          # s1*e1 + s2*e2 = 1
m = pow(c1, s1, n) * pow(c2, s2, n) % n
flag = long_to_bytes(m)

## 防御建议
- 同一 (n) 下禁止用不同指数加密相同消息；更根本地，避免多用户共享模数。
- 使用标准填充 (OAEP)，使每次加密的明文在数学上互不相同，破坏 m 的同幂结构。
- 密钥生成必须使用良好随机源，防止共模 / 共素数等批量生成问题。
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk
from Crypto.Util.number import long_to_bytes


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def main():
    vals = {}
    for line in open("output.txt", encoding="utf-8"):
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = int(v.strip(), 16)
    n, e1, e2, c1, c2 = (vals[k] for k in ("n", "e1", "e2", "c1", "c2"))
    g, s1, s2 = egcd(e1, e2)
    assert g == 1
    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    print(long_to_bytes(m).decode())


if __name__ == "__main__":
    main()
