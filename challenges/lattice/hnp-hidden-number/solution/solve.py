"""题解：hnp-hidden-number
## 漏洞点
侧信道把 (a*x + b) mod p 的高 32 位泄露了出来。写成
v = leak·2^224 + e（0 ≤ e < 2^224），代入 v ≡ a·x + b (mod p) 整理得
a·x − e ≡ c (mod p)，其中 c = (leak·2^224 − b) mod p。这正是隐数问题
（HNP）的标准形式：未知 x 与每条样本的小误差 e 由随机系数 a 连接。
14 条样本共泄露 14×32 = 448 bit 信息，远超 256 bit 的 p，格中存在
唯一远短于其他向量的目标向量，LLL 可以稳定找到它。

## 利用思路
1. 读 samples.json，取 p 与 14 条样本 [a, b, leak]。
2. 把每条样本化为 HNP 标准型：c_i = (leak_i·2^224 − b_i) mod p，
   得到方程组 a_i·x − e_i ≡ c_i (mod p)，|e_i| < 2^224。
3. 调 ctfk.solve_hnp(samples, p, 2^224)：它构造 Boneh-Venkatesan 格
   （a_i 行 + p 的模约简行 + CVP 嵌入目标行）并 LLL 约简。
4. 从最短向量中读出 x（自动尝试 ±符号并用 |e_i| < B 验证）。
5. long_to_bytes(x) 即为 flag（x 是 25 字节 flag 的大端整数）。

## 关键代码
data = json.load(open("samples.json"))
p = data["p"]
samples = [(a, (leak * (1 << 224) - b) % p)
           for a, b, leak in data["samples"]]
x = ctfk.solve_hnp(samples, p, 1 << 224)   # a*x - e ≡ c (mod p), |e| < 2^224
print(ctfk.l2b(x).decode())

## 防御建议
- 侧信道防护是根本：常数时间实现、掩化、噪声注入，避免泄露任何
  中间值的高位比特。
- 若确需容忍部分泄露，应保证泄露总量显著小于模数长度（每条泄露
  越多、所需样本越少；HNP 上界约为 n·leak_bits ≥ log2 p 即不安全）。
- 随机掩码 a 必须真随机且一次性；重用 a 会立即线性化解方程组。
"""
import json
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    data = json.load(open("samples.json", encoding="utf-8"))
    p = data["p"]
    samples = []
    for a, b, leak in data["samples"]:
        # v = leak*2^224 + e ≡ a*x + b  →  a*x - e ≡ leak*2^224 - b (mod p)
        c = (leak * (1 << 224) - b) % p
        samples.append((a, c))
    x = ctfk.solve_hnp(samples, p, 1 << 224)
    assert x is not None, "HNP 格攻击失败"
    print(ctfk.l2b(x).decode())


if __name__ == "__main__":
    main()
