"""题解：des-mitm
## 漏洞点
双重 DES 的两把密钥各自只有 16 位熵 (key = 2 字节索引 + 6 个零字节)。
对已知明文对, 双重加密可以「中间相遇」: E_k2(E_k1(pt)) 的内外两半可以
分开穷举, 各只有 2^16 种。用一张 2^16 的哈希表把 2^32 的组合搜索换成了
约 2 × 2^16 次 DES 运算加一次查表——内存换时间的经典范例。

## 利用思路
1. 读 known_pair.txt 得已知明文对 (pt, ct), 各 16 字节 = 2 个 DES 块。
2. 对全部 65536 个 k1 计算 E_k1(pt 第一块), 存入表 {密文块: k1}。
3. 对全部 65536 个 k2 计算 D_k2(ct 第一块); 查表命中即得候选 (k1, k2)。
4. 用第二块明文验证候选, 排除 2^-32 量级的偶然碰撞。
5. 用恢复的 (k1, k2) 逐块解密 target.txt, 去尾部 NUL 字节得 flag。
   (DES 密钥校验位被忽略, 命中的可能与原密钥「函数等价」, 解密结果相同。)

## 关键代码
table = {}
for k1 in range(65536):
    table.setdefault(DES.new(K(k1), MODE_ECB).encrypt(pt[:8]), k1)
for k2 in range(65536):
    x = DES.new(K(k2), MODE_ECB).decrypt(ct[:8])
    if x in table and E_k2(E_k1(pt[8:16])) == ct[8:16]:
        k1, k2 = table[x], k2

## 防御建议
- 密钥每一位都必须来自 CSPRNG; 任何「约定零位」都会把搜索空间砍成平方级。
- 双重 DES 本身不安全 (中间相遇 ~2^57 次运算), 需要双密钥强度时用 AES-128。
- 协议迁移时区分「密钥长度声明」与「实际熵」, 审计工具应检查密钥的
  实际熵而非字段宽度。
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk  # noqa: F401
from Crypto.Cipher import DES


def des_key(i):
    return i.to_bytes(2, "big") + b"\x00" * 6


def read_hex_kv(path):
    vals = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = bytes.fromhex(v.strip())
    return vals


def main():
    kp = read_hex_kv("known_pair.txt")
    pt, ct = kp["pt"], kp["ct"]
    target = read_hex_kv("target.txt")["target"]
    assert len(pt) == 16 and len(ct) == 16

    table = {}
    for k1 in range(65536):
        table.setdefault(DES.new(des_key(k1), DES.MODE_ECB).encrypt(pt[:8]), k1)
    hit = None
    for k2 in range(65536):
        x = DES.new(des_key(k2), DES.MODE_ECB).decrypt(ct[:8])
        if x in table:
            k1 = table[x]
            e = DES.new(des_key(k2), DES.MODE_ECB).encrypt(
                DES.new(des_key(k1), DES.MODE_ECB).encrypt(pt[8:16]))
            if e == ct[8:16]:
                hit = (k1, k2)
                break
    assert hit is not None, "MITM found no key pair"
    k1, k2 = hit

    out = b""
    for i in range(0, len(target), 8):
        blk = target[i:i + 8]
        inner = DES.new(des_key(k2), DES.MODE_ECB).decrypt(blk)
        out += DES.new(des_key(k1), DES.MODE_ECB).decrypt(inner)
    print(out.rstrip(b"\x00").decode())


main()
