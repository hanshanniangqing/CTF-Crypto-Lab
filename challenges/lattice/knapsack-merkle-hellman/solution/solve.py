"""题解：knapsack-merkle-hellman
## 漏洞点
Merkle-Hellman 用超增序列 w 与模乘 (r, M) 把私钥伪装成公钥
pub[i] = w[i]*r mod M，加密只是 0/1 背包求和。本题每个字节 8 bit，
公钥约 13 bit，子集和密度 d = 8/13 ≈ 0.61，远低于 LLL 可解的临界值
0.9408（CJLOSS 改进后约 0.9408 仍适用）。低密度子集和问题可以整体
放进一个格：把 0/1 选择变量平移成 ±1 后，向量
(2b_0-1, ..., 2b_{n-1}-1, 0) 是格中的极短向量，LLL 一约简就现形。

## 利用思路
1. 读入 8 个公钥 pub[0..7] 与 26 个子集和（每个对应 flag 的一个字节）。
2. 对每个子集和独立构造 dim-9 的 CJLOSS 格：
   行 i = 2e_i + 2·pub[i]·e_8（i = 0..7），末行 = (1,...,1, 2·csum)。
3. 组合 Σ bits_i·row_i − 末行 = (2b_j−1, ..., 0)，其前 8 个坐标全为 ±1、
   末坐标为 0，LLL 约简后它会作为基向量出现。
4. 扫描约简基：末坐标为 0 且前 8 个坐标 ∈ {±1} 的行，
   +1 ↔ 该位为 1、−1 ↔ 该位为 0（整体反号时相反，两种映射都试）。
5. 用 Σ bits[j]·pub[j] == csum 校验，按 bits[j] << j 累加还原字节；
   26 个字节按序拼接即得 flag（bit0 = 最低位，与加密一致）。

## 关键代码
rows = []
for i in range(8):
    row = [0] * 9
    row[i] = 2
    row[8] = 2 * pub[i]
    rows.append(row)
rows.append([1] * 8 + [2 * csum])
for vec in ctfk.lll(rows):
    if vec[8] == 0 and all(x in (-1, 1) for x in vec[:8]):
        bits = [1 if x == 1 else 0 for x in vec[:8]]  # 及其反号再验
        if sum(b * p for b, p in zip(bits, pub)) == csum:
            byte = sum(b << j for j, b in enumerate(bits))

## 防御建议
- 放弃 Merkle-Hellman 这类可归约为低密度子集和的构造；提高密度只会
  让公钥/密文爆炸，且高密度变体另有针对性攻击。
- 若教学需要保留背包体制，应增大维度并混入多轮模乘/置换，但仍无
  可证明安全性，不能用于真实场景。
- 现代格基密码应使用 NTRU / Kyber 等经过格攻击充分检验的方案。
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def read_ints(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(int(line))
    return out


def cjloss_recover(pub, csum):
    """CJLOSS 格攻击: 从子集和 csum = Σ bits[j]*pub[j] 恢复 8 bit 明文"""
    n = len(pub)
    rows = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 2
        row[n] = 2 * pub[i]
        rows.append(row)
    rows.append([1] * n + [2 * csum])
    for vec in ctfk.lll(rows):
        if vec[n] != 0:
            continue
        v = vec[:n]
        if not all(x in (-1, 1) for x in v):
            continue
        for sgn in (1, -1):
            bits = [1 if sgn * x == 1 else 0 for x in v]
            if sum(b * p for b, p in zip(bits, pub)) == csum:
                return sum(b << j for j, b in enumerate(bits))
    return None


def main():
    pub = read_ints("pubkey.txt")
    ct = read_ints("ciphertext.txt")
    assert len(pub) == 8 and ct, "附件格式异常"
    flag = bytes(cjloss_recover(pub, c) for c in ct)
    print(flag.decode())


if __name__ == "__main__":
    main()
