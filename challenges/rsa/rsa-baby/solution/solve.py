"""题解：rsa-baby
## 漏洞点
模数 n 只有 80 bit（两个 40 bit 素数之积），远低于任何安全强度。
RSA 的安全性建立在「大整数分解困难」上，而对这种规模直接跑因式分解
（试除 + Pollard rho）毫秒级即可得到 p、q——安全前提完全不存在。

## 利用思路
1. 读附件 output.txt 中的 n, e, c（十六进制）。
2. 用 ctfk.factorint(n) 分解出两个素因子 p, q。
3. 计算 phi = (p-1)(q-1)，d = e^-1 mod phi。
4. m = c^d mod n，转回字节得到 flag 正文，套上 flag{} 输出。

## 关键代码
fac = ctfk.factorint(n)
p, q = list(fac)
d = ctfk.modinv(e, (p - 1) * (q - 1))
body = long_to_bytes(pow(c, d, n)).decode()
print("flag{" + body + "}")

## 防御建议
- 模数至少 2048 bit，且必须由密码学安全随机源生成素数。
- 密钥上线前做强度审计（模数 bit 长度、素数来源可追溯）。
- 私钥/素数一旦疑似泄露立即吊销并更换。
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
    n, e, c = vals["n"], vals["e"], vals["c"]
    fac = ctfk.factorint(n)
    assert len(fac) == 2, f"unexpected factorization: {fac}"
    p, q = list(fac)
    d = ctfk.modinv(e, (p - 1) * (q - 1))
    m = pow(c, d, n)
    body = long_to_bytes(m).decode()
    print("flag{" + body + "}")


if __name__ == "__main__":
    main()
