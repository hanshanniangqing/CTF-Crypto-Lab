"""题解：hill-knownpt
## 漏洞点
Hill 密码是模 26 上的线性变换: ct = pt * K (mod 26)。线性意味着只要
拿到足够多的已知明密文对, 恢复密钥就是一个模 26 的线性方程组求解问题,
与 K 的"随机性"毫无关系。泄露几块已知明文, 整个密钥随之泄露。

## 利用思路
1. 解析 hill.txt: 4 组已知明文/密文块 (3 字母/块) + 待解密的 flag 密文。
2. 从 4 组已知对中任取 3 组组成 3x3 明文矩阵 P 与密文矩阵 C, 解
   P * K = C (mod 26): ctfk.hill_key_from_knownpt 内部做模 26 高斯消元
   (主元需与 26 互素)。矩阵不可逆时换一组 3 块的组合再试。
3. 用第 4 组已知对验证恢复出的 K (重加密应与密文一致)。
4. 用同样方法以密文为"明文"反解出 K^-1, 对 flag 密文计算 ct * K^-1
   (mod 26) 得到明文, 去掉尾部 x 填充后正则提取 flag 正文。

## 关键代码
K = ctfk.hill_key_from_knownpt(pt3, ct3)      # P*K=C (mod 26)
Kinv = ctfk.hill_key_from_knownpt(ct3, pt3)   # 反解 K^-1
fp = ctfk.mat_mul_mod(flag_ct, Kinv, 26)      # 解密 flag 块
print("flag{" + re.search(r"flag([a-z]+)", text).group(1) + "}")

## 防御建议
- 任何确定性线性密码 (Hill/仿射) 都无法抵抗已知明文攻击, 不要用于保密。
- 若必须使用, 需配合大随机数填充使明文块不可预测, 但这已超出其设计能力。
- 密钥应定期更换, 避免同一密钥下累积大量明密文对。
- 现代对称加密 (如 AES) 通过 S 盒与多轮结构抵抗线性/差分分析。
"""
import pathlib
import re
import sys
from itertools import combinations

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def to_nums(s):
    return [ord(c) - 97 for c in s]


def to_text(rows):
    return "".join(chr(97 + v) for row in rows for v in row)


def main():
    pairs, flag_ct = [], None
    for line in open("hill.txt", encoding="utf-8"):
        line = line.strip()
        if line.startswith("pt="):
            a, b = line.split()
            pairs.append((to_nums(a[3:]), to_nums(b[3:])))
        elif line.startswith("ct="):
            flag_ct = [to_nums(t) for t in line[3:].split()]
    assert len(pairs) == 4 and flag_ct, "hill.txt 格式不符合预期"

    # 在 4 组已知对中选 3 组的组合, 恢复 K 并用全部 4 组验证
    K = Kinv = None
    for combo in combinations(range(4), 3):
        pts = [pairs[i][0] for i in combo]
        cts = [pairs[i][1] for i in combo]
        cand = ctfk.hill_key_from_knownpt(pts, cts)
        if cand is None:
            continue
        if all(ctfk.mat_mul_mod([p], cand, 26)[0] == c for p, c in pairs):
            K, Kinv = cand, ctfk.hill_key_from_knownpt(cts, pts)
            break
    assert K is not None, "已知明文对不足以恢复 K"

    plain = to_text(ctfk.mat_mul_mod(flag_ct, Kinv, 26)).rstrip("x")
    m = re.search(r"flag([a-z]+)", plain)
    assert m, "解密结果中未找到 flag 片段"
    print("flag{" + m.group(1) + "}")


if __name__ == "__main__":
    main()
