"""题解：rsa-broadcast
## 漏洞点
同一条消息 m 用 e=3 加密发给 3 个互素模数不同的接收者，且无填充。
单个密文 c_i = m^3 mod n_i 发生了回绕（m^3 > n_i），单独开立方无用；
但把 3 个同余式用 CRT 合并到模 N = n1·n2·n3 上，由于 m^3 < N，
合并结果就是整数意义下精确的 m^3——Håstad 广播攻击。

## 利用思路
1. 读附件中的 (n1,c1), (n2,c2), (n3,c3)。
2. 用 ctfk.crt 把三个 c_i 合并成一个模 N 的同余值 x。
3. 此时 x = m^3（精确），用 ctfk.iroot(x, 3) 开整数立方根得 m。
4. 校验 m^3 == x 后转回字节即得 flag。

## 关键代码
x, N = ctfk.crt([(c1, n1), (c2, n2), (c3, n3)])
m = ctfk.iroot(x, 3)
assert m ** 3 == x
print(long_to_bytes(m).decode())

## 防御建议
- 使用 RSA-OAEP 等随机化填充：每次加密的明文整数不同，共模/广播结构被破坏。
- 同一消息发给多个接收者时避免共用小指数 e 且 k < e 个接收者。
- 密钥批量生成必须各用独立随机源，防止模数相关。
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
    pairs = [(vals["c1"], vals["n1"]), (vals["c2"], vals["n2"]), (vals["c3"], vals["n3"])]
    x, mod = ctfk.crt(pairs)
    m = ctfk.iroot(x, 3)
    assert m ** 3 == x, "CRT merge did not yield an exact cube (unexpected)"
    print(long_to_bytes(m).decode())


if __name__ == "__main__":
    main()
