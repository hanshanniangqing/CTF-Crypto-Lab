"""题解：lwe-toy
## 漏洞点
这是一个玩具级 Regev 型 LWE：q = 251，n = 5，m = 24，秘密 s_j ∈ {-1,0,1}，
噪声 e_i ∈ [-3,3]。格密码的安全性来自"短向量难找"，而这里 (e, s) 两个
成分都小到离谱——把它们一起放进 Kannan 嵌入格后，目标向量 (±e, ±s, ±W)
的范数只有约 6，而随机 q-ary 格的 Gauss 启发式最短向量长约 110，差距悬殊，
dim-30 的 LLL 足以直接把基约简到含目标向量的形态。

## 利用思路
1. 读 lwe.json：q=251、A（m×n）、b（m 维）、ct（hex）。
2. 构造 dim = m+n+1 = 30 的嵌入格：
   - m 行 q·e_i：提供 mod q 的自由度；
   - n 行取 A 的第 j 列、并在坐标 m+j 处放 1：把秘密 s 纳入同一格；
   - 目标行 (b, 0,...,0, W)，W=4 为嵌入权重。
   目标组合 −Σ s_j·col_j + q·Z 使首 m 坐标 = −e，得短向量 (−e, s, −W)。
3. LLL 约简后扫描基行：末坐标为 ±W 的行，令 t = 末坐标/W（±1），
   候选 s = −t·(该行中间 n 个坐标)，s_j 必须落在 {-1,0,1}。
4. 由 b ≡ A·s + e (mod q) 反推 e（对称 lifting 到 [-q/2, q/2]），
   要求 |e_i| ≤ 3，同时校验符号配对（目标行系数 ±1 两种情形通用）。
5. key = SHA256(bytes(s_j+1))，keystream 为 SHA256 链式扩展到 len(ct)
   字节，ct XOR keystream 即 flag。

## 关键代码
for vec in ctfk.lll(rows):
    if not vec[-1] or vec[-1] % W: continue
    t = vec[-1] // W                          # 目标行系数 ±1
    s = [-t * x for x in vec[m:m + n]]        # 中间 n 坐标携带 s
    if any(x not in (-1, 0, 1) for x in s): continue
    es = [(b[i] - sum(A[i][j] * s[j] for j in range(n))) % q for i in range(m)]
    if all(min(x, q - x) <= 3 for x in es):   # 噪声确实极小 → s 正确
        return s

## 防御建议
- 参数是原罪：实用 LWE 需要 n ≥ 数百维、取整高斯噪声、q 与噪声宽度
  保持安全的比值；q=251/噪声±3 的实例在笔记本上毫秒可破。
- 不要用主密钥 s 直接确定性派生流密钥加密长数据——s 一旦恢复所有
  历史密文同时沦陷；应对每条消息用新鲜随机数并经 KDF 派生会话密钥。
- 上线前用格约简工具（LLL/BKZ 模拟器）评估具体参数的攻击成本。
"""
import hashlib
import json
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def recover_s(q, A, b, W=4):
    """Kannan 嵌入格攻击: b_i = Σ A[i][j]*s[j] + e_i (mod q), |e_i|<=3, s∈{-1,0,1}"""
    m = len(A)
    n = len(A[0])
    dim = m + n + 1
    rows = []
    for i in range(m):
        row = [0] * dim
        row[i] = q
        rows.append(row)
    for j in range(n):
        row = [0] * dim
        for i in range(m):
            row[i] = A[i][j]
        row[m + j] = 1
        rows.append(row)
    trow = [0] * dim
    for i in range(m):
        trow[i] = b[i]
    trow[dim - 1] = W
    rows.append(trow)

    for vec in ctfk.lll(rows):
        if not vec[-1] or vec[-1] % W:
            continue
        t = vec[-1] // W
        if t not in (-1, 1):
            continue
        s = [-t * x for x in vec[m:m + n]]
        if any(x not in (-1, 0, 1) for x in s):
            continue
        ok = True
        for i in range(m):
            e_i = (b[i] - sum(A[i][j] * s[j] for j in range(n))) % q
            if e_i > q // 2:
                e_i -= q
            if abs(e_i) > 3:
                ok = False
                break
        if ok:
            return s
    return None


def keystream(key, length):
    ks = b""
    prev = key
    while len(ks) < length:
        prev = hashlib.sha256(prev).digest()
        ks += prev
    return ks[:length]


def main():
    data = json.load(open("lwe.json", encoding="utf-8"))
    q, n, A, b = data["q"], data["n"], data["A"], data["b"]
    ct = bytes.fromhex(data["ct"])
    s = None
    for W in (4, 2, 3, 5, 6, 7, 8):
        s = recover_s(q, A, b, W=W)
        if s is not None:
            break
    assert s is not None and len(s) == n, "LLL 未能恢复 LWE 秘密 s"
    key = hashlib.sha256(bytes((sj + 1) for sj in s)).digest()
    flag = ctfk.xor_bytes(ct, keystream(key, len(ct)))
    print(flag.decode())


if __name__ == "__main__":
    main()
