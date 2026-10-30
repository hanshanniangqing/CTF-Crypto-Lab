"""题解：dsa-biased-nonce
## 漏洞点
签名设备的随机数发生器只有 224 位熵：每个 nonce k < 2^224，相对 256 位的
模数 q 最高 32 位恒为 0。由签名方程 s·k ≡ h + r·x (mod q) 变形可得
k ≡ s^{-1}h + s^{-1}r·x (mod q)：把未知的 k 看作"小误差项"，x 就是唯一的
大未知数——这正是隐数问题 (HNP) 的标准形态。12 条签名累计泄露
12×32 = 384 bit，远超 q 的 256 bit，LLL 格归约可以唯一确定 x。

## 利用思路
1. 对每条签名求模逆：k ≡ s^{-1}·h + s^{-1}·r·x (mod q)。
2. 记 A = s^{-1}·r, B = s^{-1}·h，则 A·x - k ≡ -B (mod q)，且 0 < k < 2^224。
3. 以 (A, -B mod q) 为样本调用 ctfk.solve_hnp(samples, q, 2**224) 恢复 x。
4. long_to_bytes(x) 即私钥（flag 的字节编码）。

## 关键代码
samples = []
for sg in sigs:
    sinv = modinv(sg["s"], q)
    samples.append((sinv * sg["r"] % q, (-sinv * sg["h"]) % q))
x = ctfk.solve_hnp(samples, q, 2 ** 224)
print(ctfk.l2b(x).decode())

## 防御建议
- nonce 必须取满模数的整个范围（256 位），任何高位/低位偏置都会泄露私钥。
- 使用 RFC 6979 确定性 nonce 或经过熵源测试的安全 RNG。
- 对签名设备做侧信道与随机性审计；上线前用已知偏置样本做 HNP 自检。
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    params = json.load(open("params.json"))
    sigs = json.load(open("sigs.json"))
    q = params["q"]
    samples = []
    for sg in sigs:
        sinv = ctfk.modinv(sg["s"], q)
        a = sinv * sg["r"] % q
        b = sinv * sg["h"] % q
        samples.append((a, (-b) % q))
    x = ctfk.solve_hnp(samples, q, 2 ** 224)
    print(ctfk.l2b(x).decode())


if __name__ == "__main__":
    main()
