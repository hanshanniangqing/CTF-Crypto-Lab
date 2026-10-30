# -*- coding: utf-8 -*-
"""pubkey + hash 分类出题脚本 (共 9 题)

pubkey: dsa-nonce-reuse, dsa-biased-nonce, elgamal-malleable,
        dh-pohlig-hellman, ecc-pohlig-hellman
hash  : md5-collision, md5-length-extension, password-rules, crc32-forgery

用法: CTF_REGEN_ONLY="<题目名>" python tools/build_d_pubkey_hash.py
"""
from build_common import *  # noqa: F401,F403  (register/rng_for/write_src/verify/BUILDERS/ctfk/LAB...)

import hashlib
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

from Crypto.Util.number import bytes_to_long, long_to_bytes

# ======================================================================
# 通用工具 (本脚本私有, 不修改 ctfk)
# ======================================================================

_SMALL_ODD = []


def _small_odd_primes(limit=2048):
    if not _SMALL_ODD:
        _SMALL_ODD.extend(n for n in range(3, limit, 2) if ctfk.is_prime(n))
    return _SMALL_ODD


def _is_probable_prime(n):
    """小素数试除 + base-2 Fermat 预筛, 通过后再用 ctfk.is_prime 确认。

    纯粹为了加速 1024-bit 级素数搜索 (ctfk.is_prime 对大数要做 32 轮 MR);
    预筛只丢弃显然的合数, 不改变最终判定结果。
    """
    if n < 2:
        return False
    for sp in _small_odd_primes():
        if n % sp == 0:
            return n == sp
    if pow(2, n - 1, n) != 1:
        return False
    return ctfk.is_prime(n)


def _sha256_int(msg):
    """sha256(msg) 的 32 字节摘要转为整数 (DSA 的 h 值)"""
    return int.from_bytes(hashlib.sha256(msg).digest()[:32], "big")


def _dsa_params(name, rng):
    """生成 DSA 参数: 256-bit 素数 q, 1024-bit 级素数 p = 2*q*t + 1,
    以及阶恰为 q 的生成元 g = h^((p-1)/q) mod p (g != 1)。"""
    q = ctfk.randprime(256, rng)
    t = rng.randrange(2 ** 767, 2 ** 768)
    while True:
        p = 2 * q * t + 1
        if _is_probable_prime(p):
            break
        t += 1
    h = rng.randrange(2, p)
    g = pow(h, (p - 1) // q, p)
    while g == 1:
        h = rng.randrange(2, p)
        g = pow(h, (p - 1) // q, p)
    return p, q, g


def _dsa_sig_ok(p, q, g, y, h, r, s):
    """标准 DSA 签名验证: v == r"""
    if not (0 < r < q and 0 < s < q):
        return False
    w = ctfk.modinv(s, q)
    u1 = h * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def _ec_pohlig_fixed(E, P, Q, factors):
    """EC 上逐位 Pohlig-Hellman (绕过 ctfk.EC.ec_pohlig 的 e>=2 缺陷)。

    ctfk.EC.ec_pohlig 缺陷说明 (已报告, 未修改 ctfk):
      其第 i 位 (i>=1) 用 base = q^(e-1-i)*Pq 作 BSGS 基点, 但该点阶为
      q^(i+1) 而非 q, BSGS 返回的是完整余项 u*q^i mod q^(i+1) 而非第 i 位
      数字 u mod q, 高位数字被污染 (如 e=2 时模 4 的余数会坍缩成 mod 2)。
      正确做法是固定 gamma = q^(e-1)*Pq (阶恰为 q), 对
      hk = q^(e-1-i)*(Qq - x_q*Pq) 求 dlog。本函数即标准实现;
      ctfk.pohlig_hellman (乘法群) 无此问题。
    factors: {q: e}, 要求 ord(P) = prod(q^e), 求 k 使 k*P = Q (k < ord(P))。
    """
    order = 1
    for q, e in factors.items():
        order *= q ** e
    residues = []
    for q, e in sorted(factors.items()):
        sub = order // q ** e
        Pq, Qq = E.mul(sub, P), E.mul(sub, Q)
        if Pq is None:
            residues.append((0, q ** e))        # ord(P) 与 q 互素, 该分量恒 0
            continue
        gamma = E.mul(q ** (e - 1), Pq)         # 阶恰为 q
        x_q = 0
        for i in range(e):
            diff = E.sub(Qq, E.mul(x_q, Pq))    # Qq - x_q*Pq
            hk = E.mul(q ** (e - 1 - i), diff)  # 落在 <gamma> 内, 阶整除 q
            d = E.ec_bsgs(gamma, hk, q)
            if d is None:
                return None
            x_q += d * q ** i
        residues.append((x_q % (q ** e), q ** e))
    k, _ = ctfk.crt(residues)
    return k


def _write_json(name, fn, obj):
    write_src(name, fn, json.dumps(obj, indent=2))


def _run_tool(folder, filename, stdin_text=""):
    """在 folder 下以子进程运行生成的工具脚本, 返回 (stdout, returncode)"""
    r = subprocess.run([sys.executable, filename], cwd=str(folder),
                       input=stdin_text, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    return r.stdout, r.returncode


# ======================================================================
# pubkey 1: dsa-nonce-reuse
# ======================================================================

DSA_REUSE_README = """DSA 随机数重用 —— 支付网关签名泄露
================================================================

风控系统导出的两条转账签名, 经审计发现它们使用了**同一个随机数 k**
(两条签名的 r 完全相同即是证据)。私钥 x 直接是本次挑战的答案
(x 的字节编码即 flag)。

文件格式 (所有数字均为十进制):
  params.json : {"p", "q", "g", "y"}
                y = g^x mod p 是公钥; q 是 256-bit 素数, p = 2*q*t + 1
  sigs.json   : [{"msg", "h", "r", "s"}, ...]
                h = sha256(msg) 的 32 字节整数 mod q
                r = (g^k mod p) mod q,  s = k^-1 * (h + x*r) mod q
"""


@register("dsa-nonce-reuse")
def gen_dsa_nonce_reuse(ch):
    name = "dsa-nonce-reuse"
    flag = ch["flag"]
    rng = rng_for(name)
    p, q, g = _dsa_params(name, rng)
    x = bytes_to_long(flag.encode())
    verify(name, x < q, "flag 整数必须小于 q (DSA 私钥范围)")
    y = pow(g, x, p)

    msgs = [b"transfer 100 ETH to alice", b"transfer 200 ETH to bob"]
    hs = [_sha256_int(m) % q for m in msgs]
    k = rng.randrange(1, q)
    r = pow(g, k, p) % q
    while r == 0:  # 概率上几乎不会发生, 但规范要求检查
        k = rng.randrange(1, q)
        r = pow(g, k, p) % q
    kin = ctfk.modinv(k, q)
    ss = [kin * (hi + x * r) % q for hi in hs]
    verify(name, all(s != 0 for s in ss), "s 不得为 0")
    verify(name, _dsa_sig_ok(p, q, g, y, hs[0], r, ss[0])
           and _dsa_sig_ok(p, q, g, y, hs[1], r, ss[1]), "生成的签名未通过标准 DSA 验证")

    _write_json(name, "params.json", {"p": p, "q": q, "g": g, "y": y})
    _write_json(name, "sigs.json", [
        {"msg": msgs[0].decode(), "h": hs[0], "r": r, "s": ss[0]},
        {"msg": msgs[1].decode(), "h": hs[1], "r": r, "s": ss[1]},
    ])
    write_src(name, "README.txt", DSA_REUSE_README)

    # ---- 自检: 用两条重用 k 的签名反推私钥 ----
    kk = (hs[0] - hs[1]) * ctfk.modinv(ss[0] - ss[1], q) % q
    xx = (ss[0] * kk - hs[0]) * ctfk.modinv(r, q) % q
    verify(name, kk == k, "k 恢复失败")
    verify(name, xx == x, "x 恢复失败")
    verify(name, ctfk.l2b(xx) == flag.encode(), "恢复出的字节不是 flag")


# ======================================================================
# pubkey 2: dsa-biased-nonce
# ======================================================================

DSA_BIASED_README = """签名设备 RNG 缺陷 —— 偏置 nonce
================================================================

某硬件签名设备的随机数发生器有缺陷: 它只产生 **224 位**随机数
(即每个 nonce k < 2^224, 相对 256-bit 的模数 q 而言最高 32 位恒为 0)。
下面导出了该设备对 12 笔付款的签名。

文件格式 (所有数字均为十进制):
  params.json : {"p", "q", "g", "y"}
  sigs.json   : [{"msg", "h", "r", "s"}, ...] 共 12 条
                h = sha256(msg) 的 32 字节整数 mod q

私钥 x 的字节编码即 flag。已知信息: 该设备的 RNG 只产生 224 位随机数
(高 32 位为 0)。
"""


@register("dsa-biased-nonce")
def gen_dsa_biased_nonce(ch):
    name = "dsa-biased-nonce"
    flag = ch["flag"]
    rng = rng_for(name)
    p, q, g = _dsa_params(name, rng)
    x = bytes_to_long(flag.encode())
    verify(name, x < q, "flag 整数必须小于 q")
    y = pow(g, x, p)

    bound = 2 ** 224
    sigs = []
    ks = []
    for i in range(12):
        k = rng.randrange(1, bound)          # 偏置: 高 32 位恒 0
        vendor = rng.randrange(999)
        msg = "payment %d to vendor-%03d" % (i, vendor)
        h = _sha256_int(msg.encode()) % q
        r = pow(g, k, p) % q
        while r == 0:
            k = rng.randrange(1, bound)
            r = pow(g, k, p) % q
        s = ctfk.modinv(k, q) * (h + x * r) % q
        ks.append(k)
        sigs.append({"msg": msg, "h": h, "r": r, "s": s})
    verify(name, all(s["s"] != 0 for s in sigs), "s 不得为 0")
    verify(name, all(k < bound for k in ks), "nonce 偏置 (k < 2^224) 不成立")
    verify(name, all(_dsa_sig_ok(p, q, g, y, sg["h"], sg["r"], sg["s"]) for sg in sigs),
           "存在未通过标准 DSA 验证的签名")

    _write_json(name, "params.json", {"p": p, "q": q, "g": g, "y": y})
    _write_json(name, "sigs.json", sigs)
    write_src(name, "README.txt", DSA_BIASED_README)

    # ---- 自检: HNP 格攻击反推私钥 (12 x 32 = 384 bit 泄露 > 256 bit) ----
    samples = []
    for sg in sigs:
        sinv = ctfk.modinv(sg["s"], q)
        a = sinv * sg["r"] % q                 # A_i = s^-1 * r
        b = sinv * sg["h"] % q                 # B_i = s^-1 * h
        samples.append((a, (-b) % q))          # A_i*x - k_i = -B_i (mod q), |k_i| < 2^224
    x_rec = ctfk.solve_hnp(samples, q, bound)
    verify(name, x_rec is not None, "solve_hnp 未能恢复私钥")
    verify(name, x_rec == x, "HNP 格攻击恢复的 x 不正确")
    verify(name, ctfk.l2b(x_rec) == flag.encode(), "恢复出的字节不是 flag")


# ======================================================================
# pubkey 3: elgamal-malleable
# ======================================================================

ELGAMAL_ORACLE = '''# -*- coding: utf-8 -*-
"""ElGamal 解密预言机 (oracle.py)

用法:
    python oracle.py
然后向 stdin 写入成对的两行: 第一行是 c1' 的 hex, 第二行是 c2' 的 hex。
预言机为每一对输出一行:
  * 若 (c1', c2') 恰为原始密文 (c1, c2): 输出 REFUSED
  * 否则输出解密结果的 hex (固定 64 字节)
可以连续查询多对, EOF 结束。

私钥 x 只存在于本文件内部 —— 但"可以被查询"本身就是攻击面。
"""
import sys

P = @@P@@
X = @@X@@
C1 = @@C1@@
C2 = @@C2@@


def decrypt(a, b):
    share = pow(a, X, P)
    try:
        return b * pow(share, -1, P) % P
    except ValueError:
        return None


def main():
    toks = sys.stdin.read().split()
    for i in range(0, len(toks) - 1, 2):
        try:
            a, b = int(toks[i], 16), int(toks[i + 1], 16)
        except ValueError:
            print("ERROR")
            continue
        if (a, b) == (C1, C2):
            print("REFUSED")
            continue
        mm = decrypt(a, b)
        print("ERROR" if mm is None else mm.to_bytes(64, "big").hex())


if __name__ == "__main__":
    main()
'''


@register("elgamal-malleable")
def gen_elgamal_malleable(ch):
    name = "elgamal-malleable"
    flag = ch["flag"]
    rng = rng_for(name)
    p = ctfk.randprime(512, rng)
    g = rng.randrange(2, p)
    x = rng.randrange(2, p)
    y = pow(g, x, p)
    m = bytes_to_long(flag.encode())
    verify(name, m < p, "明文必须小于 p")
    k = rng.randrange(2, p)
    c1 = pow(g, k, p)
    c2 = m * pow(y, k, p) % p

    write_src(name, "params.txt", (
        "ElGamal 公开参数与截获密文 (十六进制)\n"
        "====================================\n"
        "p  = %x\n"
        "g  = %x\n"
        "y  = %x      (公钥, y = g^x mod p)\n"
        "c1 = %x\n"
        "c2 = %x      (明文 m 的加密; m 的字节编码即 flag)\n\n"
        "解密预言机: python oracle.py (stdin 每两行一对 c1'/c2' 的 hex, 用法见文件头)\n"
        "注意: 预言机拒绝解密原始密文 (c1, c2) 本身。\n"
        % (p, g, y, c1, c2)
    ))
    write_src(name, "oracle.py", (ELGAMAL_ORACLE
                                  .replace("@@P@@", str(p))
                                  .replace("@@X@@", str(x))
                                  .replace("@@C1@@", str(c1))
                                  .replace("@@C2@@", str(c2))))

    # ---- 自检 1: 数学上反推 ----
    share = pow(c1, x, p)
    m_back = c2 * ctfk.modinv(share, p) % p
    verify(name, m_back == m, "用私钥解密未恢复出 m")
    share2 = share  # (c1, 2*c2) 解密得 2m mod p
    m2 = 2 * c2 * ctfk.modinv(share2, p) % p
    verify(name, m2 == 2 * m % p, "(c1, 2*c2) 应解密为 2m mod p")
    verify(name, m2 * ctfk.modinv(2, p) % p == m, "模逆 2^-1 未恢复出 m")
    verify(name, c1 == pow(g, k, p) and y == pow(g, x, p), "参数不自洽")

    # ---- 自检 2: 实际运行 oracle.py ----
    d = src_dir(name)
    out1, rc1 = _run_tool(d, "oracle.py", "%x\n%x\n" % (c1, c2))
    verify(name, rc1 == 0 and out1.strip() == "REFUSED", "oracle 未拒绝原始密文")
    out2, rc2 = _run_tool(d, "oracle.py", "%x\n%x\n" % (c1, 2 * c2 % p))
    got = int(out2.strip(), 16)
    verify(name, rc2 == 0 and got == 2 * m % p, "oracle 对 (c1, 2*c2) 的解密结果错误")
    verify(name, got * ctfk.modinv(2, p) % p == m, "经 oracle 恢复 m 失败")


# ======================================================================
# pubkey 4: dh-pohlig-hellman
# ======================================================================


@register("dh-pohlig-hellman")
def gen_dh_pohlig_hellman(ch):
    name = "dh-pohlig-hellman"
    flag = ch["flag"]
    rng = rng_for(name)
    x = bytes_to_long(flag.encode())
    # 构造光滑素数: p - 1 = 2 * (10~14 个 16~20 bit 素数), 因子全部 <= 2^20。
    # (乘 2 是必须的: 全奇素数之积为奇数, p = M+1 将恒为偶数。)
    while True:
        n_factors = rng.randrange(10, 15)
        primes = [ctfk.randprime(rng.randrange(16, 21), rng) for _ in range(n_factors)]
        m = 2
        for q0 in primes:
            m *= q0
        p = m + 1
        if m > x and _is_probable_prime(p):   # 保证 x < p-1 (Pohlig-Hellman 可恢复)
            break
    factors = ctfk.factorint(p - 1)

    # 找阶为 p-1 的生成元 g
    g = 2
    while any(pow(g, (p - 1) // q0, p) == 1 for q0 in factors):
        g += 1
    h = pow(g, x, p)

    write_src(name, "dh.txt", (
        "Diffie-Hellman 公开参数 (十六进制)\n"
        "==================================\n"
        "p = %x\n"
        "g = %x\n"
        "h = %x\n\n"
        "h = g^x mod p, x 是私钥 (其字节编码即 flag)。\n"
        "备注: 这次选的素数有点特别 —— p-1 是光滑的 (smooth)。\n"
        % (p, g, h)
    ))

    # ---- 自检: 分解 p-1 并用 Pohlig-Hellman 反推 x ----
    f2 = ctfk.factorint(p - 1)
    x2 = ctfk.pohlig_hellman(g, h, p, f2)
    verify(name, p > 2 ** 240, "p 尺寸不足")
    verify(name, ctfk.is_prime(p), "p 素性异常")
    verify(name, max(f2) <= 2 ** 20, "p-1 不光滑 (存在 > 2^20 的因子)")
    verify(name, x2 is not None and x2 == x, "Pohlig-Hellman 未能恢复 x")
    verify(name, ctfk.l2b(x2) == flag.encode(), "恢复出的字节不是 flag")
    verify(name, pow(g, x2, p) == h, "g^x2 != h")


# ======================================================================
# pubkey 5: ecc-pohlig-hellman
# ======================================================================

ECC_README = """椭圆曲线离散对数挑战
================================================================

曲线: E: y^2 = x^3 + 1  (mod p)      即 short Weierstrass 形式 a=0, b=1
域:   F_p, p 见 ecc.json (素数, p ≡ 11 (mod 12), 即 p ≡ 2 (mod 3))
      该曲线是**超奇异**的: #E(F_p) = p + 1
基点: G (其阶恰为 #E(F_p) = p + 1)
公钥: Q = k*G, k 为私钥标量

数据格式见 ecc.json: {"p": ..., "a": 0, "b": 1, "G": [x, y], "Q": [x, y]}
恢复出 k 后, 其字节编码即 flag 主体: flag{<k 的字节>}。
"""


@register("ecc-pohlig-hellman")
def gen_ecc_pohlig_hellman(ch):
    name = "ecc-pohlig-hellman"
    flag = ch["flag"]
    rng = rng_for(name)
    body = flag[len("flag{"):-1]               # "3cc_p0hlig"
    k_secret = bytes_to_long(body.encode())

    # 构造超奇异曲线参数: M = 12 * (若干 12~14 bit 素数) 完全光滑, p = M - 1。
    # M 是 12 的倍数 ⇒ p = M-1 ≡ 11 (mod 12): 既是素数, 又使 y^2=x^3+1
    # 为超奇异曲线 (#E = p+1 = M), 且 p ≡ 3 (mod 4) 便于开平方根。
    while True:
        n_factors = rng.randrange(6, 9)
        primes = [ctfk.randprime(rng.randrange(12, 15), rng) for _ in range(n_factors)]
        m = 12
        for q0 in primes:
            m *= q0
        if m <= 2 ** 84:
            continue                            # 保证 k (80 bit) < N = p+1
        p = m - 1
        if _is_probable_prime(p):
            break

    n_order = p + 1                             # = M, 曲线阶
    curve = ctfk.EC(0, 1, p)
    fac = ctfk.factorint(n_order)

    # 找阶为 n_order 的基点 G: x 从 2 开始试, p ≡ 3 (mod 4) 可开平方根
    g_pt = None
    gx = 1
    while g_pt is None:
        gx += 1
        rhs = (gx ** 3 + 1) % p
        gy = pow(rhs, (p + 1) // 4, p)
        if gy * gy % p != rhs:
            continue                            # rhs 非二次剩余, 换下一个 x
        cand = (gx, gy)
        # 要求 G 是满阶点: 对每个素因子 q, (N/q)*G 不得为无穷远点
        if all(curve.mul(n_order // q0, cand) is not None for q0 in fac):
            g_pt = cand
    q_pt = curve.mul(k_secret, g_pt)

    _write_json(name, "ecc.json", {
        "p": p, "a": 0, "b": 1,
        "G": [g_pt[0], g_pt[1]],
        "Q": [q_pt[0], q_pt[1]],
    })
    write_src(name, "README.txt", ECC_README)

    # ---- 自检: 分解曲线阶并用 (修正版) Pohlig-Hellman 反推 k ----
    # 注: ctfk.EC.ec_pohlig 在 e>=2 的素数幂上数字位有缺陷 (N 含 2^2 必触发),
    #     此处用 _ec_pohlig_fixed 绕过, bug 详见该函数 docstring 与最终报告。
    k2 = _ec_pohlig_fixed(curve, g_pt, q_pt, ctfk.factorint(n_order))
    verify(name, p % 12 == 11, "p 不满足 p ≡ 11 (mod 12)")
    verify(name, ctfk.is_prime(p), "p 素性异常")
    verify(name, max(fac) <= 2 ** 14, "曲线阶不够光滑 (存在 > 2^14 的因子)")
    verify(name, curve.on(g_pt) and curve.on(q_pt), "点不在曲线上")
    verify(name, k_secret < n_order, "k 必须 < 曲线阶 N")
    verify(name, k2 is not None and k2 == k_secret, "ec_pohlig 未能恢复 k")
    verify(name, "flag{" + ctfk.l2b(k2).decode() + "}" == flag, "由 k 重组 flag 失败")


# ======================================================================
# hash 1: md5-collision
# ======================================================================

MD5_COLLISION_VERIFY = '''# -*- coding: utf-8 -*-
"""MD5 碰撞校验器。

在当前工作目录读取 good.bin 与 evil.bin, 要求:
  * 两者 MD5 完全相同
  * 两者 SHA256 不同 (即不能是同一个文件)
  * good.bin 以 colliding_base_1.bin 的内容开头
  * evil.bin 以 colliding_base_2.bin 的内容开头
  * 两者长度都超过 200 字节 (不能直接提交原始碰撞块)
全部通过则输出 flag。
"""
import hashlib
import sys

GOOD_BASE = open("colliding_base_1.bin", "rb").read()
EVIL_BASE = open("colliding_base_2.bin", "rb").read()
FLAG = "@@FLAG@@"


def die(msg):
    print("VERIFY-FAIL: " + msg)
    sys.exit(1)


def load(fn, base):
    try:
        data = open(fn, "rb").read()
    except OSError as e:
        die("无法读取 %s: %s" % (fn, e))
    if len(data) <= 200:
        die("%s 长度 %d 未超过 200 字节" % (fn, len(data)))
    if not data.startswith(base):
        die("%s 未以对应的 colliding_base 开头" % fn)
    return data


good = load("good.bin", GOOD_BASE)
evil = load("evil.bin", EVIL_BASE)
if hashlib.md5(good).digest() != hashlib.md5(evil).digest():
    die("两文件的 MD5 不相同")
if hashlib.sha256(good).digest() == hashlib.sha256(evil).digest():
    die("两文件 SHA256 相同 (内容一样?)")
print(FLAG)
'''


@register("md5-collision")
def gen_md5_collision(ch):
    name = "md5-collision"
    flag = ch["flag"]
    a = (LAB / "lib" / "data" / "md5_collision_a.bin").read_bytes()
    b = (LAB / "lib" / "data" / "md5_collision_b.bin").read_bytes()
    tail = b"\nBUILD-MANIFEST v1 internal use only\n"
    base1, base2 = a + tail, b + tail
    write_src(name, "colliding_base_1.bin", base1)
    write_src(name, "colliding_base_2.bin", base2)
    write_src(name, "verify.py", MD5_COLLISION_VERIFY.replace("@@FLAG@@", flag))

    # ---- 自检 1: 追加相同尾巴后 MD5 仍碰撞、SHA256 分开 ----
    suffix = b"\napproved: yes\n" + b"#" * 64
    good, evil = base1 + suffix, base2 + suffix
    verify(name, hashlib.md5(a).digest() == hashlib.md5(b).digest()
           and len(a) == len(b), "原始碰撞块对不成立")
    verify(name, hashlib.md5(good).digest() == hashlib.md5(evil).digest(),
           "追加尾巴后 MD5 不再碰撞")
    verify(name, hashlib.sha256(good).digest() != hashlib.sha256(evil).digest(),
           "SHA256 应当不同")
    verify(name, len(good) > 200 and len(evil) > 200, "长度须 > 200")
    verify(name, good.startswith(base1) and evil.startswith(base2), "前缀条件不满足")

    # ---- 自检 2: 实际运行 verify.py ----
    with tempfile.TemporaryDirectory() as td:
        for fn in ("colliding_base_1.bin", "colliding_base_2.bin", "verify.py"):
            shutil.copy(str(src_dir(name) / fn), td)
        Path(td, "good.bin").write_bytes(good)
        Path(td, "evil.bin").write_bytes(evil)
        out, rc = _run_tool(td, "verify.py")
        verify(name, rc == 0 and flag in out, "verify.py 未输出 flag")


# ======================================================================
# hash 2: md5-length-extension (server 类)
# ======================================================================

LENEXT_SERVER = '''# -*- coding: utf-8 -*-
"""MD5 长度扩展挑战服务器 (secret-prefix MAC)。

启动: python server.py --port N   (--port 0 表示由系统分配端口)
行协议:
  连接后服务器先发送一行:
      MAC for data=<content 的 hex>: <md5(secret||content) 的 hex>
  之后客户端每发送一行: SUBMIT <data 的 hex> <mac 的 hex>
  服务器检查: data 须以原始 content 开头, 且包含 b";admin=true",
              且 md5(secret||data) == mac。
  通过则回 GRANTED <flag>, 否则回 REJECTED。

⚠️ 安全反模式说明: 真实系统绝不应把密钥硬编码在源码里。本文件出于教学
目的将 SECRET 以逐字节 XOR 0x5A 的混淆形式存放 (你可以读出来, 这允许;
但本题的标准解法是 MD5 长度扩展攻击 —— 不需要知道密钥本身)。
"""
import argparse
import hashlib
import socket
import sys

_ENC = @@ENC@@
SECRET = bytes(b ^ 0x5A for b in _ENC)
CONTENT = b"amount=100;to=alice;"
FLAG = "@@FLAG@@"


def mac(data):
    return hashlib.md5(SECRET + data).hexdigest()


def handle(conn):
    f = conn.makefile("rwb")
    try:
        f.write(("MAC for data=%s: %s\\n" % (CONTENT.hex(), mac(CONTENT))).encode())
        f.flush()
        while True:
            raw = f.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3 or parts[0] != "SUBMIT":
                f.write(b"BADREQ\\n")
                f.flush()
                continue
            try:
                data = bytes.fromhex(parts[1])
                given = parts[2].lower()
            except ValueError:
                f.write(b"BADREQ\\n")
                f.flush()
                continue
            ok = (data.startswith(CONTENT)
                  and b";admin=true" in data
                  and hashlib.md5(SECRET + data).hexdigest() == given)
            f.write((("GRANTED " + FLAG if ok else "REJECTED") + "\\n").encode())
            f.flush()
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(5)
    sys.stdout.write("READY %d\\n" % srv.getsockname()[1])
    sys.stdout.flush()
    while True:
        conn, _addr = srv.accept()
        handle(conn)


if __name__ == "__main__":
    main()
'''


def _lenext_attack(host, port):
    """对 (host, port) 上的 server 执行完整长度扩展攻击 (含未知密钥长度爆破)。
    返回 GRANTED 行中的 flag 或 None。"""
    s = socket.create_connection((host, port), timeout=5)
    try:
        f = s.makefile("rwb")
        line = f.readline().decode().strip()
        body = line[len("MAC for data="):]
        content_hex, digest_hex = body.rsplit(": ", 1)
        content = bytes.fromhex(content_hex)
        digest = bytes.fromhex(digest_hex)
        for secret_len in range(8, 33):
            appendix, new_mac = ctfk.md5_lenext(digest, secret_len + len(content),
                                                b";admin=true")
            data = content + appendix
            f.write(("SUBMIT %s %s\n" % (data.hex(), new_mac.hex())).encode())
            f.flush()
            reply = f.readline().decode().strip()
            if reply.startswith("GRANTED"):
                return reply.split(None, 1)[1]
        return None
    finally:
        s.close()


@register("md5-length-extension")
def gen_md5_length_extension(ch):
    name = "md5-length-extension"
    flag = ch["flag"]
    secret = b"S3cr3tMACk3y2026"
    content = b"amount=100;to=alice;"
    enc = [b0 ^ 0x5A for b0 in secret]
    write_src(name, "server.py", (LENEXT_SERVER
                                  .replace("@@ENC@@", repr(enc))
                                  .replace("@@FLAG@@", flag)))

    # ---- 自检 1: 本地模拟长度扩展 (不走网络) ----
    digest = hashlib.md5(secret + content).digest()
    verify(name, len(secret) == 16, "SECRET 应为 16 字节")
    appendix, new_mac = ctfk.md5_lenext(digest, len(secret) + len(content), b";admin=true")
    data = content + appendix
    verify(name, hashlib.md5(secret + data).digest() == new_mac,
           "长度扩展伪造的 MAC 未通过 md5(secret||data) 校验")
    verify(name, data.startswith(content) and b";admin=true" in data,
           "伪造 data 不满足服务器的业务条件")
    verify(name, bytes(b0 ^ 0x5A for b0 in enc) == secret, "SECRET 异或混淆不自洽")

    # ---- 自检 2: 启动 server.py 做一次端到端攻击 ----
    d = src_dir(name)
    proc = subprocess.Popen([sys.executable, "server.py", "--port", "0"],
                            cwd=str(d), stdout=subprocess.PIPE)
    got = None
    try:
        ready = proc.stdout.readline().decode().strip()
        verify(name, ready.startswith("READY"), "server 未发送 READY 行")
        port = int(ready.split()[1])
        time.sleep(0.05)
        got = _lenext_attack("127.0.0.1", port)
    finally:
        proc.kill()
    verify(name, got == flag, "端到端长度扩展攻击未取得 flag")


# ======================================================================
# hash 3: password-rules
# ======================================================================

_LEET_TABLE = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})


def _leet(s):
    return s.translate(_LEET_TABLE)


@register("password-rules")
def gen_password_rules(ch):
    name = "password-rules"
    flag = ch["flag"]
    rng = rng_for(name)

    words_all = [w.strip() for w in
                 (LAB / "lib" / "data" / "wordlist.txt").read_text(encoding="utf-8").splitlines()
                 if w.strip()]
    cand = [w for w in words_all if 6 <= len(w) <= 8 and w.isalpha() and w.islower()]
    verify(name, len(cand) >= 100, "6~8 长度词太少")
    w1, w2, w3, w4 = rng.sample(cand, 4)
    year = rng.randrange(1980, 2010)

    pw1 = w1 + str(year)
    pw2 = w2.capitalize()
    pw3 = w3 + "!"
    pw4 = _leet(w4)
    pw5 = _leet("password") + "2026"
    pws = [pw1, pw2, pw3, pw4, pw5]
    users = ["user1", "user2", "user3", "user4", "user5 (admin)"]
    hashes = [hashlib.md5(pw.encode()).hexdigest() for pw in pws]

    write_src(name, "hashes.txt", (
        "# 泄露的口令哈希 (MD5, 无盐)\n"
        "# 格式: <32位小写md5>  <用户名>\n"
        + "\n".join("%s  %s" % (h, u) for h, u in zip(hashes, users)) + "\n"
    ))
    write_src(name, "wordlist.txt",
              (LAB / "lib" / "data" / "wordlist.txt").read_text(encoding="utf-8"))

    # ---- 自检 1: pw5 与 index.json 的 flag 一致 ----
    verify(name, "flag{" + pw5 + "}" == flag, "pw5 与 flag 不一致")

    # ---- 自检 2: 规则引擎枚举须能覆盖全部 5 条哈希 (与 solve 同思路) ----
    years = [str(yv) for yv in range(1900, 2031)]
    targets = {h: u for h, u in zip(hashes, users)}
    expected = dict(zip(hashes, pws))
    found = {}
    for w in words_all:
        base_forms = [w, w.capitalize(), w + "!", _leet(w)]
        year_forms = [w + yv for yv in years] + [_leet(w) + yv for yv in years]
        for form in base_forms + year_forms:
            h = hashlib.md5(form.encode()).hexdigest()
            if h in targets and h not in found:
                found[h] = form
        if len(found) == len(targets):
            break
    verify(name, len(found) == len(targets), "规则引擎未能覆盖全部 5 条哈希")
    for h, u in zip(hashes, users):
        verify(name, found.get(h) == expected[h],
               "%s 的哈希被错误的规则命中" % u)
    verify(name, found[hashes[4]] == pw5, "admin 条目未恢复出 pw5")


# ======================================================================
# hash 4: crc32-forgery
# ======================================================================

CRC32_VERIFY = '''# -*- coding: utf-8 -*-
"""CRC32 伪造校验器。

在当前工作目录读取 forged.txt, 要求:
  * CRC32 与原始申诉信完全一致 (0x@@CRC@@)
  * 内容包含 "ACCESS GRANTED"
  * 内容不包含 "guest"
  * 长度与原始申诉信不同
全部通过则输出 flag。
"""
import sys
import zlib

APPEAL = @@APPEAL@@
TARGET_CRC = @@CRC@@
FLAG = "@@FLAG@@"


def die(msg):
    print("VERIFY-FAIL: " + msg)
    sys.exit(1)


try:
    forged = open("forged.txt", "rb").read()
except OSError as e:
    die("无法读取 forged.txt: %s" % e)

if zlib.crc32(forged) != TARGET_CRC:
    die("CRC32 与原始申诉信不一致")
if b"ACCESS GRANTED" not in forged:
    die("缺少 ACCESS GRANTED")
if b"guest" in forged:
    die("内容仍包含 guest")
if len(forged) == len(APPEAL):
    die("长度与原始申诉信相同")
print(FLAG)
'''


@register("crc32-forgery")
def gen_crc32_forgery(ch):
    name = "crc32-forgery"
    flag = ch["flag"]
    appeal = b"Dear admin, please unban user guest. Reason: he said sorry.\n"
    target_crc = zlib.crc32(appeal) & 0xFFFFFFFF

    write_src(name, "appeal.txt", appeal)
    write_src(name, "verify.py", (CRC32_VERIFY
                                  .replace("@@CRC@@", "0x%08x" % target_crc)
                                  .replace("@@APPEAL@@", repr(appeal))
                                  .replace("@@FLAG@@", flag)))

    # ---- 自检 1: CRC32 线性补丁构造伪造文件 ----
    prefix = b"Dear admin, ACCESS GRANTED for user hero."
    patch = ctfk.crc32_patch(prefix, target_crc)
    forged = prefix + patch
    verify(name, patch is not None and zlib.crc32(forged) == target_crc,
           "CRC32 补丁未命中目标值")
    verify(name, b"ACCESS GRANTED" in forged, "伪造件缺少 ACCESS GRANTED")
    verify(name, b"guest" not in forged, "伪造件仍包含 guest")
    verify(name, len(forged) != len(appeal), "长度应与原始申诉信不同")

    # ---- 自检 2: 实际运行 verify.py ----
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(str(src_dir(name) / "verify.py"), td)
        Path(td, "forged.txt").write_bytes(forged)
        out, rc = _run_tool(td, "verify.py")
        verify(name, rc == 0 and flag in out, "verify.py 未输出 flag")


if __name__ == "__main__":
    run_builders(BUILDERS)
