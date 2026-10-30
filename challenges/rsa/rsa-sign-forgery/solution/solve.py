"""题解：rsa-sign-forgery
## 漏洞点
验证器是教科书式 RSA 签名：s ↦ s³ mod n，只检查结果字节串以
"I am the admin" 开头——没有哈希、没有填充、没有长度约束。e=3 时
立方映射在整数上足够「稠密」：把目标前缀 M 左移 k 个零字节得到窗口
[M·256^k, (M+1)·256^k)，k 足够大时窗口宽于相邻立方数的间隔
（约 3s²），必有一个完全立方数 s³ 落入其中。于是 s 是无需私钥的
合法签名——签名只是个可以自己挑的立方根。

## 利用思路
1. 读 pub.txt 得 n, e=3；目标前缀 M = 整数化的 33 字节消息。
2. 对 k = 0,1,2,...：令 T = M·256^k，取 s = ⌈T^(1/3)⌉（ctfk.iroot 后
   逐个 +1 微调）。
3. 若 s³ 恰落入 [T, (M+1)·256^k) 且 s³ < n，则 s³ 未回绕，
   long_to_bytes(s³) = M 的字节 + k 个低字节 → 前缀校验必过。
4. 把 s 写入 sig.txt，运行 python verify.py，验证器输出 flag。

## 关键代码
for k in range(200):
    T, HI = M << (8*k), (M + 1) << (8*k)
    s = ctfk.iroot(T, 3)
    while s ** 3 < T:
        s += 1
    if s ** 3 < HI and s ** 3 < n:
        break            # s 即伪造签名

## 防御建议
- 签名必须先哈希再签（RSASSA-PSS/PKCS#1 v1.5），并对编码做全结构校验。
- 拒绝任何「检查部分字节/前缀」的自制验证逻辑。
- e=3 需格外审慎；常规实现选 e=65537 并配合填充与长度检查。
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    vals = {}
    for line in open("pub.txt", encoding="utf-8"):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        try:
            vals[k.strip()] = int(v.strip(), 16)
        except ValueError:
            continue
    n, e = vals["n"], vals["e"]
    msg = b"I am the admin: grant root access"
    M = int.from_bytes(msg, "big")
    sig = None
    for k in range(200):
        lo_t = M << (8 * k)
        hi_t = (M + 1) << (8 * k)
        s = max(ctfk.iroot(lo_t, e), 1)
        while s ** e < lo_t:
            s += 1
        if s ** e < hi_t and s ** e < n:
            sig = s
            break
    assert sig is not None, "no cube lands in the target window (unexpected)"
    with open("sig.txt", "w", encoding="utf-8") as f:
        f.write("%x\n" % sig)
    r = subprocess.run([sys.executable, "verify.py"], cwd=os.getcwd(),
                       capture_output=True, text=True, timeout=60)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    print(out)
    if "flag{" not in out:
        raise SystemExit("verify.py rejected the forged signature")


if __name__ == "__main__":
    main()
