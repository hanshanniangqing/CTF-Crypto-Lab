"""题解：rsa-coppersmith
## 漏洞点
侧信道泄露了素数 p 的高 112 位（p_high = p >> 48，低 48 位未知）。
Coppersmith 方法（Howgrave-Graham + LLL）可以求多项式 f(x) =
p_high·2^48 + x 在模 n 下小于 n^0.25 的根：只要未知量 x0 < 2^48
远小于该界，格约简就能把 f(x0) = p 「顶」出来，从而完整分解 n。

## 利用思路
1. 读附件中的 n, e, c, p_high。
2. 构造首一多项式 f(x) = (p_high << 48) + x，未知低 48 位为 x0。
3. 调 ctfk.small_roots(f, n, beta=0.5, X=2^48, m=3, t=3) 求根。
4. 由根重构 p = (p_high << 48) + x0（校验 n % p == 0），q = n // p。
5. d = e^-1 mod (p-1)(q-1)，m = c^d mod n，转回字节即得 flag。

## 关键代码
roots = ctfk.small_roots([p_high << 48, 1], n, 0.5, 1 << 48, m=3, t=3)
p = next((p_high << 48) + r for r in roots if r >= 0 and n % ((p_high << 48) + r) == 0)
d = ctfk.modinv(e, (p - 1) * (n // p - 1))

## 防御建议
- 私钥的任何比特（哪怕高位）都不得通过侧信道、日志、核心转储泄露。
- 侧信道防护：恒定时间实现、掩码、禁用交换文件/内存转储中的密钥页。
- 密钥材料零化：使用后清零内存，避免长期驻留可被读取的存储。
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk
from Crypto.Util.number import long_to_bytes


def main():
    vals = {}
    for line in open("output.txt", encoding="utf-8"):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        try:
            vals[k.strip()] = int(v.strip(), 16)
        except ValueError:
            continue
    n, e, c, p_high = vals["n"], vals["e"], vals["c"], vals["p_high"]
    leak_bits = 48  # 题面: p 的低 48 位未知
    # beta 取 0.49 而非 0.5: small_roots 用 gcd(f(x0), n) >= n^beta 过滤候选根,
    # 而泄露的素数可能是两因子中较小的一个 (< sqrt(n)), beta=0.5 会把真根拒掉;
    # 对 320-bit n 恒有 p >= 2^159 > n^0.49 (<= 2^157), 0.49 必然放行。
    roots = ctfk.small_roots([p_high << leak_bits, 1], n, 0.49,
                             1 << leak_bits, m=3, t=3)
    p = None
    for r in roots:
        if r < 0:
            continue
        cand = (p_high << leak_bits) + r
        if cand > 1 and cand < n and n % cand == 0:
            p = cand
            break
    assert p is not None, f"coppersmith failed, roots={roots[:5]}"
    q = n // p
    d = ctfk.modinv(e, (p - 1) * (q - 1))
    print(long_to_bytes(pow(c, d, n)).decode())


if __name__ == "__main__":
    main()
