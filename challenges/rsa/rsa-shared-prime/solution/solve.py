"""题解：rsa-shared-prime
## 漏洞点
批量生成密钥时随机源异常，两个不同模数 n1、n2 共享了同一个素数 p。
n1 = p·q1，n2 = p·q2，于是 gcd(n1, n2) = p——本应对大数分解保密的
素数被一次欧几里得除法直接暴露，两把锁同时作废。

## 利用思路
1. 读附件中的 n1, n2, e, c1。
2. g = gcd(n1, n2) 即共享素数 p；q1 = n1 // p。
3. phi = (p-1)(q1-1)，d = e^-1 mod phi。
4. m = c1^d mod n1，转回字节即得 flag。

## 关键代码
p = gcd(n1, n2)              # 共享素数直接现形
q1 = n1 // p
d = ctfk.modinv(e, (p - 1) * (q1 - 1))
print(long_to_bytes(pow(c1, d, n1)).decode())

## 防御建议
- 批量生成密钥必须使用密码学安全随机源（/dev/urandom 等），禁止弱种子。
- 部署前对全部模数做两两 gcd 普查（也防与公网已知模数撞素数）。
- 密钥生成后立即销毁中间状态，避免同批素数被复用。
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
    n1, n2, e, c1 = vals["n1"], vals["n2"], vals["e"], vals["c1"]
    p = ctfk.math.gcd(n1, n2)
    assert 1 < p < min(n1, n2), "gcd(n1, n2) is trivial (unexpected)"
    q1 = n1 // p
    d = ctfk.modinv(e, (p - 1) * (q1 - 1))
    print(long_to_bytes(pow(c1, d, n1)).decode())


if __name__ == "__main__":
    main()
