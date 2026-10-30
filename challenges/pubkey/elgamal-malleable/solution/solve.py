"""题解：elgamal-malleable
## 漏洞点
教科书式 ElGamal 密文 (c1, c2) = (g^k, m·y^k) 具有乘法同态性：
(c1, t·c2) 解密后恰为 t·m mod p——任何人无需私钥即可"加工"密文。
解密预言机虽然拒绝解密原始密文 (c1, c2)，却没有防住同态变形：
把 c2 翻倍再查询，就拿回了 2m，一次模逆即可还原 m。

## 利用思路
1. 读 params.txt 得 p, c1, c2（十六进制）。
2. 构造变形密文 (c1, 2·c2 mod p)，通过 stdin 发给 oracle.py。
3. 预言机解出 2·m mod p 并以 hex 返回（不等于原始密文，不会被拒绝）。
4. 本地乘 2^{-1} mod p 恢复 m，转字节即 flag。

## 关键代码
query = "%x\\n%x\\n" % (c1, 2 * c2 % p)
out = subprocess.run([sys.executable, "oracle.py"], input=query,
                     capture_output=True, text=True).stdout
m2 = int(out.strip(), 16)
m = m2 * pow(2, -1, p) % p
print(ctfk.l2b(m).decode())

## 防御建议
- 不要对外提供"裸解密预言机"；确需提供时先做密文完整性校验（CCA 安全变换）。
- 使用 ECIES（ElGamal + 对称封装 + MAC）等带认证的方案，破坏同态可塑性。
- 对同一会话的重复/关联查询限速并审计，异常查询直接告警。
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    vals = {}
    for line in open("params.txt", encoding="utf-8"):
        if "=" in line and not line.startswith(("解密", "注意")):
            k, v = line.split("=", 1)
            k = k.strip()
            if k in ("p", "g", "y", "c1", "c2"):
                vals[k] = int(v.split("(")[0].strip(), 16)
    p, c1, c2 = vals["p"], vals["c1"], vals["c2"]
    query = "%x\n%x\n" % (c1, 2 * c2 % p)
    r = subprocess.run([sys.executable, "oracle.py"], input=query,
                       capture_output=True, text=True, timeout=30)
    m2 = int(r.stdout.strip(), 16)
    m = m2 * ctfk.modinv(2, p) % p
    print(ctfk.l2b(m).decode())


if __name__ == "__main__":
    main()
