# -*- coding: utf-8 -*-
"""格密码 (lattice) 分类出题脚本 (共 3 题): knapsack-merkle-hellman,
hnp-hidden-number, lwe-toy"""
import hashlib
import json
import math

from build_common import *


# ============================================================
# 公共: CJLOSS 背包格攻击 (与 solution/solve.py 保持同一构造)
# ============================================================
def _cjloss_recover_byte(pub, csum):
    """对单个子集和 csum = sum(bits[j]*pub[j]) 做 CJLOSS 格攻击.

    格构造 (dim n+1): 行 i = 2e_i + 2*pub[i]*e_n, 末行 = (1,...,1, 2*csum).
    组合向量 sum(bits_i*row_i) - last = (2*b_0-1, ..., 2*b_{n-1}-1, 0) ∈ {±1}^n × {0}.
    返回恢复的字节 (0..255) 或 None.
    """
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


# ============================================================
# 1. knapsack-merkle-hellman — Merkle-Hellman 背包 (CJLOSS 格攻击)
# ============================================================
@register("knapsack-merkle-hellman")
def gen_knapsack_merkle_hellman(ch):
    name = "knapsack-merkle-hellman"
    flag = ch["flag"]
    fbytes = flag.encode()
    rng = rng_for(name)

    # 超增序列 w[0..7]: w[0] ∈ [1,5], w[i] = sum(w[:i]) + rng(1, 2^(i+3))
    w = [rng.randint(1, 5)]
    for i in range(1, 8):
        w.append(sum(w) + rng.randint(1, 2 ** (i + 3)))
    total = sum(w)
    M = total + rng.randint(1, total)
    r = rng.randrange(2, M)
    while math.gcd(r, M) != 1:
        r = rng.randrange(2, M)
    pub = [w[i] * r % M for i in range(8)]

    # 每个字节一个低密度子集和: bit j (j=0 为最低位) 携带 pub[j]
    ciphertext = [sum(((b >> j) & 1) * pub[j] for j in range(8)) for b in fbytes]

    write_src(
        name, "pubkey.txt",
        "# Merkle-Hellman 背包公钥\n"
        "# 格式: 每行一个十进制数, 共 8 行, 依次为 pub[0..7] = w[i]*r mod M\n"
        + "\n".join(str(x) for x in pub) + "\n",
    )
    write_src(
        name, "ciphertext.txt",
        "# Merkle-Hellman 密文\n"
        "# 格式: 每行一个十进制子集和, 共 %d 行 (flag 的每个字节对应一行)\n"
        "# 明文字节 b 加密为 sum_{j=0..7} ((b>>j)&1) * pub[j]  (bit0 = 最低位)\n"
        % len(ciphertext)
        + "\n".join(str(x) for x in ciphertext) + "\n",
    )

    # ---- 自检 ----
    verify(name, all(w[i] > sum(w[:i]) for i in range(1, 8)) and M > total,
           "超增序列/模数条件不成立 (w 严格超增且 M > sum(w))")
    verify(name, math.gcd(r, M) == 1, "r 与 M 不互素")
    # 私钥反推: t = c*r^{-1} mod M 后对超增序列贪心
    rinv = ctfk.modinv(r, M)
    dec = []
    for c in ciphertext:
        t = c * rinv % M
        byte = 0
        for j in range(7, -1, -1):
            if t >= w[j]:
                t -= w[j]
                byte |= 1 << j
        dec.append(byte)
    verify(name, bytes(dec) == fbytes, "私钥贪心解密未恢复 flag")
    # 攻击视角: 逐字节 CJLOSS 格攻击
    for idx, c in enumerate(ciphertext):
        verify(name, _cjloss_recover_byte(pub, c) == fbytes[idx],
               f"CJLOSS 格攻击第 {idx} 字节失败")


# ============================================================
# 2. hnp-hidden-number — 隐数问题 HNP (Boneh-Venkatesan 格)
# ============================================================
@register("hnp-hidden-number")
def gen_hnp_hidden_number(ch):
    name = "hnp-hidden-number"
    flag = ch["flag"]
    rng = rng_for(name)

    p = ctfk.randprime(256, rng)
    x = ctfk.b2l(flag.encode())
    verify(name, x < p, "flag 对应整数必须小于 p")

    # 14 个样本: v = (a*x + b) mod p, 泄露 v 的高 32 位 (低 224 位未知)
    samples = []
    for _ in range(14):
        a = rng.randrange(1, p)
        b = rng.randrange(1, p)
        v = (a * x + b) % p
        leak = v >> 224
        samples.append([a, b, leak])

    write_src(
        name, "samples.json",
        json.dumps({"p": p, "samples": samples}, indent=2) + "\n",
    )
    write_src(
        name, "README.txt",
        "hnp-hidden-number 附件说明\n"
        "==========================\n"
        "samples.json 内容:\n"
        "  p        : 256-bit 素数\n"
        "  samples  : 14 个样本 [a_i, b_i, leak_i] (均为十进制整数)\n\n"
        "侧信道对秘密 x 每次采样给出:\n"
        "  v    = (a*x + b) mod p\n"
        "  leak = v >> 224   (即 v 的最高 32 位; 低 224 位未知)\n\n"
        "也就是每条样本泄露了 x 在随机掩码 a 下的约 32 bit 信息,"
        "14 条样本共 448 bit, 足以把 x 完全格出来。\n",
    )

    # ---- 自检 ----
    verify(name, ctfk.is_prime(p), "p 不是素数")
    verify(name, all(0 <= leak < 2 ** 32 for _, _, leak in samples),
           "leak 必须落在 32 bit 内")
    # 攻击视角: HNP 标准形式 a_i*x - e_i ≡ c_i (mod p), |e_i| < 2^224
    cs = [(a, (leak * 2 ** 224 - b) % p) for a, b, leak in samples]
    x_rec = ctfk.solve_hnp(cs, p, 2 ** 224)
    verify(name, x_rec == x, "solve_hnp 未恢复秘密 x")


# ============================================================
# 3. lwe-toy — LWE 小规模原语攻击 (Kannan 嵌入格)
# ============================================================
def _lwe_lattice_attack(q, A, b, W=4):
    """Kannan 嵌入格攻击恢复 LWE 秘密 s. 失败返回 None.

    格 (dim m+n+1):
      行 i∈[0,m) : q*e_i                       (模 q)
      行 j∈[0,n) : (A[0][j],...,A[m-1][j], e_{m+j})   (A 的第 j 列 + 单位块, 把 s 纳入格)
      目标行     : (b, 0,...,0, W)             (嵌入权重 W)
    目标短向量: t_row - sum_j s_j*col_j + q*Z = (-e, s, -W) (或其反号/
    目标行系数为 +1 的等价形式 (e, -s, W)), 故恢复规则为:
      v[-1] = t*W (t=±1) → s = -t*v[m:m+n], 再由 b ≡ A*s + e 反推 e 并要求 |e_i| 很小.
    """
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
        if vec[-1] == 0 or vec[-1] % W != 0:
            continue
        t = vec[-1] // W
        if t not in (-1, 1):
            continue
        s_cand = [-t * x for x in vec[m:m + n]]
        if any(x not in (-1, 0, 1) for x in s_cand):
            continue
        ok = True
        for i in range(m):
            e_i = (b[i] - sum(A[i][j] * s_cand[j] for j in range(n))) % q
            if e_i > q // 2:
                e_i -= q
            if abs(e_i) > 3:
                ok = False
                break
        if ok:
            return s_cand
    return None


@register("lwe-toy")
def gen_lwe_toy(ch):
    name = "lwe-toy"
    flag = ch["flag"]
    fbytes = flag.encode()
    rng = rng_for(name)

    q, n, m = 251, 5, 24
    s = [rng.choice([-1, 0, 1]) for _ in range(n)]
    A = [[rng.randrange(q) for _ in range(n)] for _ in range(m)]
    e = [rng.randint(-3, 3) for _ in range(m)]
    b = [(sum(A[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(m)]

    # 对称层: key = SHA256(bytes(s_j+1)), keystream = SHA256 链式扩展
    key = hashlib.sha256(bytes((sj + 1) for sj in s)).digest()
    ks = b""
    prev = key
    while len(ks) < len(fbytes):
        prev = hashlib.sha256(prev).digest()
        ks += prev
    ks = ks[:len(fbytes)]
    ct = ctfk.xor_bytes(fbytes, ks)

    write_src(
        name, "lwe.json",
        json.dumps({"q": q, "n": n, "m": m, "A": A, "b": b, "ct": ct.hex()},
                   indent=2) + "\n",
    )
    write_src(
        name, "README.txt",
        "lwe-toy 附件说明\n"
        "================\n"
        "这是一个玩具级的 Regev 型 LWE 实例:\n"
        "  q = 251, n = 5, m = 24\n"
        "  秘密 s_j ∈ {-1, 0, 1}        (极小秘密)\n"
        "  噪声 e_i ∈ [-3, 3]           (极小噪声)\n"
        "  b_i = (sum_j A[i][j]*s[j] + e_i) mod q\n\n"
        "lwe.json 字段:\n"
        "  q, n, m : 参数\n"
        "  A       : m x n 公开矩阵 (元素 ∈ [0, q))\n"
        "  b       : m 维样本向量\n"
        "  ct      : flag 密文 (hex)\n\n"
        "flag 的加密方式 (恢复 s 后即可解):\n"
        "  key      = SHA256(bytes(s_j + 1 for j in 0..n-1))\n"
        "  keystream: 从 key 开始反复 SHA256 链式拼接, 截取前 len(flag) 字节\n"
        "             (ks = b\"\"; prev = key; while len(ks) < L: prev = SHA256(prev); ks += prev)\n"
        "  ct       = flag XOR keystream\n\n"
        "噪声和秘密都极小, (e, s) 可以一起放进 Kannan 嵌入格, LLL 一击即中。\n",
    )

    # ---- 自检 ----
    verify(name, all((sum(A[i][j] * s[j] for j in range(n)) + e[i]) % q == b[i]
                     for i in range(m)), "LWE 方程 b ≡ A·s + e (mod q) 不成立")
    # 对称层反推: 复现 keystream 解出 flag
    ks2 = b""
    prev = key
    while len(ks2) < len(fbytes):
        prev = hashlib.sha256(prev).digest()
        ks2 += prev
    verify(name, ctfk.xor_bytes(ct, ks2[:len(fbytes)]) == fbytes,
           "keystream 复现/XOR 未恢复 flag")
    # 攻击视角: Kannan 嵌入格恢复 s (本题成败关键)
    s_rec = None
    for W_try in (4, 2, 3, 5, 6, 7, 8):
        s_rec = _lwe_lattice_attack(q, A, b, W=W_try)
        if s_rec is not None:
            verify(name, W_try == 4, f"默认嵌入权重 W=4 失效, 实际使用 W={W_try}")
            break
    verify(name, s_rec == s, "格攻击未恢复 LWE 秘密 s")


if __name__ == "__main__":
    run_builders(BUILDERS)
