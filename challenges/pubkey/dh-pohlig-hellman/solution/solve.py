"""题解：dh-pohlig-hellman
## 漏洞点
Diffie-Hellman 的安全性不仅依赖 p 的尺寸，更依赖 p-1 的因子结构：离散对数
的安全性下界由 p-1 的**最大素因子**决定。本题生成 p 时没有约束 p-1，它完全
光滑（所有素因子 ≤ 2^20）。Pohlig-Hellman 算法把 mod p 的离散对数拆成每个
小素因子子群上的小对数，各自用大步小步 (BSGS, 约 sqrt(2^20)=1024 步) 解出，
再用中国剩余定理合并——"光滑素数，光滑攻破"。

## 利用思路
1. 读 dh.txt 得 p, g, h（十六进制）。
2. ctfk.factorint(p-1) 把 p-1 分解成全部小素因子。
3. ctfk.pohlig_hellman(g, h, p, factors) 逐子群求对数并 CRT 合并，恢复 x。
4. x 即私钥（flag 的整数编码），转字节得到 flag。

## 关键代码
factors = ctfk.factorint(p - 1)
x = ctfk.pohlig_hellman(g, h, p, factors)
print(ctfk.l2b(x).decode())

## 防御建议
- 生成素数时强制检查 p-1 含有大素因子（如 safe prime p = 2q+1，q 为大素数）。
- 直接使用标准化群参数（RFC 7919 ffdhe2048 等），不要自造 p。
- 协议实现要防御 Logjam 式参数降级：固定群清单并拒绝未审计的参数。
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    import re
    vals = {}
    for line in open("dh.txt", encoding="utf-8"):
        m = re.match(r"^(p|g|h) = ([0-9a-f]+)\s*$", line)
        if m:
            vals[m.group(1)] = int(m.group(2), 16)
    p, g, h = vals["p"], vals["g"], vals["h"]
    factors = ctfk.factorint(p - 1)
    x = ctfk.pohlig_hellman(g, h, p, factors)
    print(ctfk.l2b(x).decode())


if __name__ == "__main__":
    main()
