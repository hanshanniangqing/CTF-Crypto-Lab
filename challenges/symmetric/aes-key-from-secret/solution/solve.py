"""题解：aes-key-from-secret
## 漏洞点
AES 密钥不是随机生成的, 而是由可枚举的用户名派生:
key = MD5(b"key:" + username)[:16]。配置泄露文件给出了全部候选用户名,
密钥空间从 2^128 塌缩成区区 7 个候选——逐个试一遍即可, 完全不需要爆破。

## 利用思路
1. 解析 leaked-config.ini, 提取 usernames 列表。
2. 对每个用户名 u 派生 key = MD5(b"key:" + u).digest()[:16]。
3. 用该 key 以 AES-ECB 解密 flag.enc (32 字节, 含 pkcs7 填充)。
4. 明文以 flag{ 开头的即为正确密钥; 其余候选解出的只是随机乱码。

## 关键代码
for u in usernames:
    key = hashlib.md5(b"key:" + u.encode()).digest()[:16]
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    if pt.startswith(b"flag{"):
        print(ctfk.pkcs7_unpad(pt).decode())

## 防御建议
- 对称密钥必须用 CSPRNG 生成 (os.urandom / secrets.token_bytes)。
- 确需从口令派生时, 用 PBKDF2/HKDF 加随机盐并抬高迭代次数,
  且用户名不应作为唯一熵源。
- 密钥与配置分离存储: 泄露一份配置文件不应等于泄露密钥。
"""
import sys
import pathlib
import hashlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk
from Crypto.Cipher import AES


def main():
    users = []
    for line in open("leaked-config.ini", encoding="utf-8"):
        if line.strip().lower().startswith("usernames"):
            users = [u.strip() for u in line.split("=", 1)[1].split(",") if u.strip()]
    ct = bytes.fromhex(open("flag.enc").read().strip())
    for u in users:
        key = hashlib.md5(b"key:" + u.encode()).digest()[:16]
        pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
        if pt.startswith(b"flag{"):
            print(ctfk.pkcs7_unpad(pt).decode())
            return
    raise SystemExit("no candidate username worked")


main()
