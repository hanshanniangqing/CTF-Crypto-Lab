# -*- coding: utf-8 -*-
"""
ctfk — CTF 密码学工具箱 (crypto toolkit)
=========================================

本库汇集了做题与出题都常用的密码学原语，全部纯 Python 实现（可选使用
pycryptodome / sympy），无网络依赖。题目生成脚本 tools/build_*.py 与各题
解答 solution/solve.py 共用本库，保证出题与解题逻辑一致。

模块速查
--------
* 数与字节   : b2l / l2b / xor_bytes / iroot / modinv / crt / hamming_bits
* 素数       : is_prime / randprime / factorint / pollard_brent
* RSA 攻击   : wiener / fermat_factor / convergents
* 离散对数   : bsgs / pohlig_hellman (乘法群) + EC 类上的 ec_bsgs / ec_pohlig
* 格         : lll (精确有理数 LLL) / small_roots (Coppersmith 单变量) /
               solve_hnp (隐数问题) / solve_lcg_params / solve_lcg_truncated
* PRNG       : MT19937 / untemper / clone_mt / LCG
* 对称       : rc4 / pkcs7_pad / pkcs7_unpad / pkcs7_valid
* 古典       : caesar_shift / vigenere / affine_decrypt / Playfair /
               Hill(模26矩阵) / BigramModel / chi2_english (英文评分)
* 哈希       : 纯Python MD5 (可做长度扩展) / md5_lenext / crc32_patch / gf2_solve
"""

import base64
import hashlib  # 仅用于测试对照
import math
import os
import random
import struct
import zlib
from fractions import Fraction

try:
    import re
except ImportError:  # pragma: no cover
    re = None

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# ======================================================================
# 数与字节
# ======================================================================

def b2l(b):
    """bytes -> int (big-endian)"""
    return int.from_bytes(b, "big")


def l2b(n, length=None):
    """int -> bytes (big-endian), 无前导零; length 指定输出长度(左补零)"""
    if n < 0:
        raise ValueError("negative int")
    bl = (n.bit_length() + 7) // 8
    if length is None:
        length = max(1, bl)
    return n.to_bytes(length, "big")


def xor_bytes(a, b):
    """异或; 短的按周期重复"""
    if len(a) < len(b):
        a = (a * (len(b) // len(a) + 1))[: len(b)]
    elif len(b) < len(a):
        b = (b * (len(a) // len(b) + 1))[: len(a)]
    return bytes(x ^ y for x, y in zip(a, b))


def iroot(n, k):
    """整数 k 次方根 (向下取整). 牛顿迭代, 精确."""
    if n < 0:
        raise ValueError("negative")
    if n in (0, 1) or k == 1:
        return n
    k = int(k)
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def modinv(a, m):
    a %= m
    return pow(a, -1, m)


def crt(pairs):
    """中国剩余定理. pairs = [(r0, m0), (r1, m1), ...], 模需两两互素."""
    r, m = 0, 1
    for r2, m2 in pairs:
        if math.gcd(m, m2) != 1:
            raise ValueError("moduli not coprime")
        r = r + m * ((r2 - r) * modinv(m, m2) % m2)
        m *= m2
    return r % m, m


def hamming_bits(a, b):
    """两等长字节串的汉明距离 (按位)"""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ======================================================================
# 素数与因式分解
# ======================================================================

def is_prime(n, rounds=32):
    """Miller-Rabin; 对 n < 3.3e24 使用确定性基"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    if n < 3317044064679887385961981:
        bases = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    else:
        bases = [random.randrange(2, n - 1) for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def randprime(bits, rng=None):
    rng = rng or random
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def pollard_brent(n):
    """Brent-Pollard rho, 返回 n 的一个非平凡因子 (n 为合数时)"""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    while True:
        y, c, m = random.randrange(1, n), random.randrange(1, n), 128
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g


_SMALL_PRIMES = []

def _small_primes_upto(limit=100000):
    global _SMALL_PRIMES
    if _SMALL_PRIMES:
        return _SMALL_PRIMES
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i:: i] = bytearray(len(sieve[i * i:: i]))
    _SMALL_PRIMES = [i for i in range(2, limit + 1) if sieve[i]]
    return _SMALL_PRIMES


def factorint(n):
    """因式分解, 返回 {素数: 指数}. 适用 n <= ~2^80 (试除 + rho)."""
    fac = {}
    for p in _small_primes_upto():
        if p * p > n:
            break
        while n % p == 0:
            fac[p] = fac.get(p, 0) + 1
            n //= p
    if n == 1:
        return fac
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            fac[m] = fac.get(m, 0) + 1
            continue
        d = pollard_brent(m)
        stack.append(d)
        stack.append(m // d)
    return dict(sorted(fac.items()))


# ======================================================================
# 连分数 / RSA 经典攻击
# ======================================================================

def convergents(a, b):
    """a/b 的连分数渐近分数, 产出 (p, q)"""
    num0, den0, num1, den1 = 0, 1, 1, 0
    while b:
        q = a // b
        a, b = b, a % b
        num0, num1 = num1, q * num1 + num0
        den0, den1 = den1, q * den1 + den0
        yield num1, den1


def wiener(e, n):
    """Wiener 攻击: d < (1/3) n^(1/4) 时恢复私钥 d. 返回 d 或 None."""
    for k, d in convergents(e, n):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = iroot(disc, 2)
        if r * r == disc and (s + r) % 2 == 0:
            return d
    return None


def fermat_factor(n, max_steps=1 << 22):
    """Fermat 分解: p, q 相近时有效. 返回 (p, q) 或 None"""
    a = iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = iroot(b2, 2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


# ======================================================================
# 离散对数 (乘法群)
# ======================================================================

def bsgs(g, h, p, order=None):
    """大步小步: 求 x 使 g^x = h (mod p). order: ord(g) 的上界."""
    if order is None:
        order = p - 1
    m = math.isqrt(order) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor = modinv(pow(g, m, p), p)
    gamma = h % p
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def _dlog_prime_subgroup(gamma, h, q):
    """在阶为素数 q 的群中求 d: gamma^d = h (BSGS)"""
    m = math.isqrt(q) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * gamma % q  # 占位防误用; 实际群运算由参数决定
    return None


def pohlig_hellman(g, h, p, factors):
    """
    Pohlig-Hellman: ord(g) 的光滑因子 factors = {q: e} (ord(g) | p-1).
    求 x 使 g^x = h (mod p), 假设 x < prod(q^e). 返回 x 或 None.
    """
    residues = []
    for q, e in sorted(factors.items()):
        cof = (p - 1) // q ** e
        g_q = pow(g, cof, p)
        h_q = pow(h, cof, p)
        x_q = 0
        gamma = pow(g_q, q ** (e - 1), p)  # 阶为 q 的元素
        # BSGS 表: gamma^j
        m = math.isqrt(q) + 1
        table = {}
        cur = 1
        for j in range(m):
            table.setdefault(cur, j)
            cur = cur * gamma % p
        gminv = modinv(pow(gamma, m, p), p)
        for i in range(e):
            hk = pow(h_q * modinv(pow(g_q, x_q, p), p) % p, q ** (e - 1 - i), p)
            d = None
            y = hk
            for j in range(m + 1):
                if y in table:
                    d = j * m + table[y]
                    break
                y = y * gminv % p
            if d is None:
                return None
            x_q += d * q ** i
        residues.append((x_q, q ** e))
    x, _ = crt(residues)
    return x


# ======================================================================
# 椭圆曲线 (short Weierstrass, 素域)
# ======================================================================

class EC:
    """y^2 = x^3 + a*x + b  (mod p), p 素数. 点为 (x, y) 元组或 None(无穷远)."""

    def __init__(self, a, b, p):
        self.a, self.b, self.p = a, b, p
        assert (4 * a ** 3 + 27 * b ** 2) % p != 0, "singular curve"

    def on(self, P):
        if P is None:
            return True
        x, y = P
        return (y * y - (x ** 3 + self.a * x + self.b)) % self.p == 0

    def add(self, P, Q):
        p = self.p
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * modinv(2 * y1, p) % p
        else:
            lam = (y2 - y1) * modinv(x2 - x1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def sub(self, P, Q):
        if Q is None:
            return P
        return self.add(P, (Q[0], (-Q[1]) % self.p))

    def neg(self, P):
        return None if P is None else (P[0], (-P[1]) % self.p)

    def mul(self, k, P):
        R, Q = None, P
        while k > 0:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    def ec_bsgs(self, P, Q, order):
        """求 k 使 k*P = Q, 0 <= k < order"""
        m = math.isqrt(order) + 1
        table = {}
        cur = None
        for j in range(m):
            table.setdefault(cur, j)
            cur = self.add(cur, P)
        factor = self.neg(self.mul(m, P))
        gamma = Q
        for i in range(m):
            if gamma in table:
                return i * m + table[gamma]
            gamma = self.add(gamma, factor)
        return None

    def ec_pohlig(self, P, Q, factors):
        """factors = {q: e}: ord(P) 的光滑分解; 求 k 使 k*P = Q.
        逐位求解: 第 i 位对固定基点 gamma = q^(e-1)·Pq (阶 q) 做小对数."""
        order = 1
        for q, e in factors.items():
            order *= q ** e
        residues = []
        for q, e in sorted(factors.items()):
            sub = order // q ** e
            Pq, Qq = self.mul(sub, P), self.mul(sub, Q)
            gamma = self.mul(q ** (e - 1), Pq)  # 阶恰为 q
            x_q = 0
            for i in range(e):
                # t = q^(e-1-i)·(Qq - x_q·Pq) = d_i · gamma
                t = self.mul(q ** (e - 1 - i), self.sub(Qq, self.mul(x_q, Pq)))
                d = self.ec_bsgs(gamma, t, q)
                if d is None:
                    return None
                x_q += d * q ** i
            residues.append((x_q, q ** e))
        k, _ = crt(residues)
        return k


# ======================================================================
# 格: 精确 LLL 与应用
# ======================================================================

def _fdot(u, v):
    return sum(x * y for x, y in zip(u, v))


def _gso(b):
    n = len(b)
    bs, mu, Bn = [], [[Fraction(0)] * n for _ in range(n)], [Fraction(0)] * n
    for i in range(n):
        v = [Fraction(x) for x in b[i]]
        for j in range(i):
            if Bn[j] == 0:
                mu[i][j] = Fraction(0)
                continue
            mu[i][j] = _fdot(v, bs[j]) / Bn[j]
            v = [vi - mu[i][j] * bj for vi, bj in zip(v, bs[j])]
        Bn[i] = _fdot(v, v)
        bs.append(v)
    return bs, mu, Bn


def lll(basis, delta=Fraction(99, 100)):
    """
    LLL 格基约简. basis: 整数矩阵, 行向量. 返回约简后的整数矩阵 (新对象).

    主实现使用 sympy 的精确 LLL (DomainMatrix.lll); sympy 不可用或格超定
    (行数 > 列数) 时退回内置的事件驱动精确实现.
    """
    rows = [list(map(int, r)) for r in basis if any(r)]
    if not rows:
        return rows
    n, cols = len(rows), len(rows[0])
    if n <= cols:
        try:
            from sympy.polys.matrices import DomainMatrix
            from sympy.polys.domains import ZZ
            M = DomainMatrix(rows, (n, cols), ZZ)
            out = M.lll().to_list()  # sympy 默认 delta, 内部精确算术
            return [list(map(int, r)) for r in out if any(r)]
        except ImportError:
            pass
        except Exception:
            # sympy 对某些输入 (如超大整数项) 的 lll 有内部断言问题 → 回退
            pass
    return _lll_fallback(rows, delta)


def _lll_fallback(basis, delta=Fraction(99, 100), max_events=100000):
    """内置精确 LLL (事件驱动, 每事件后全量重算 GSO). 供 sympy 不可用时使用."""
    b = [list(map(int, row)) for row in basis]
    n = len(b)
    events = 0
    while events < max_events:
        bs, mu, Bn = _gso(b)
        acted = False
        for k in range(1, n):
            for j in range(k - 1, -1, -1):
                x = mu[k][j]
                r = math.floor(x + Fraction(1, 2))
                if r:
                    b[k] = [bk - r * bj for bk, bj in zip(b[k], b[j])]
                    acted = True
                    break
            if acted:
                break
        if not acted:
            for k in range(1, n):
                lhs = Bn[k] + mu[k][k - 1] ** 2 * Bn[k - 1]
                if lhs < delta * Bn[k - 1]:
                    b[k - 1], b[k] = b[k], b[k - 1]
                    acted = True
                    break
        if not acted:
            return [row for row in b if any(row)]
        events += 1
    return [row for row in b if any(row)]


def babai(basis, target):
    """Babai 最近平面法 (内部先做 LLL). target 同维度整数向量.
    返回格中离 target 最近的向量."""
    B = lll(basis)
    n = len(B)
    bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
    for i in range(n):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            nb = _fdot(bs[j], bs[j])
            if nb == 0:
                continue
            mu[i][j] = _fdot(v, bs[j]) / nb
            v = [vi - mu[i][j] * bj for vi, bj in zip(v, bs[j])]
        bs.append(v)
    t = [Fraction(x) for x in target]
    coeffs = [0] * n
    for i in range(n - 1, -1, -1):
        nb = _fdot(bs[i], bs[i])
        if nb == 0:
            coeffs[i] = 0
            continue
        ci = _fdot(t, bs[i]) / nb
        r = math.floor(ci + Fraction(1, 2))
        coeffs[i] = r
        t = [ti - r * bj for ti, bj in zip(t, B[i])]
    return [sum(coeffs[i] * B[i][j] for i in range(n)) for j in range(len(B[0]))]


# ---- 多项式 (系数列表, 低次在前) ----

def poly_trim(p):
    p = list(p)
    while p and p[-1] == 0:
        p.pop()
    return p


def poly_mul(a, b, n=None):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] += ai * bj
    if n is not None:
        r = [c % n for c in r]
    return poly_trim(r)


def poly_eval(p, x, n):
    r = 0
    for c in reversed(p):
        r = (r * x + c) % n
    return r


def poly_gcd_modn(a, b, n):
    """
    多项式 gcd over Z/nZ. 返回 (g, factor):
    正常时 factor=None; 若某步首项系数不可逆, 则 gcd(该系数, n) 是 n 的
    非平凡因子, 以 factor 返回 (g 为 None) — Franklin-Reiter 的附带福利.
    """
    a = poly_trim([c % n for c in a])
    b = poly_trim([c % n for c in b])
    while b:
        try:
            inv = modinv(b[-1], n)
        except ValueError:
            return None, math.gcd(b[-1], n)
        c0 = a[-1] * inv % n
        shift = len(a) - len(b)
        a = list(a)
        for i, c in enumerate(b):
            a[shift + i] = (a[shift + i] - c * c0) % n
        a = poly_trim(a)
        if len(a) < len(b):
            a, b = b, a
    # 首一化
    if a:
        try:
            inv = modinv(a[-1], n)
        except ValueError:
            return None, math.gcd(a[-1], n)
        a = [c * inv % n for c in a]
    return a, None


def _int_roots_mod(h, bound):
    """
    求整系数多项式 h 在 (-bound, bound) 内的全部整数根.
    方法: 模小素数求根 + 增量 CRT 组合 (完全确定性, 无数值收敛问题).
    """
    h = poly_trim(h)
    if len(h) < 2:
        return []
    primes, prod = [], 1
    ps = 65521
    while prod < 2 * bound and len(primes) < 12:
        while not is_prime(ps):
            ps += 2
        primes.append(ps)
        prod *= ps
        ps += 2
    if not primes:
        return []
    roots_per = []
    for p_ in primes:
        hm = [c % p_ for c in h]
        rs = [x for x in range(p_) if poly_eval(hm, x, p_) == 0]
        if not rs:
            return []
        roots_per.append(rs)
    out = set()

    def dfs(i, cur, mod):
        if len(out) > 64:
            return
        if i == len(primes):
            for cand in (cur, cur - prod):
                if -bound < cand < bound:
                    val = 0
                    for cc in reversed(h):
                        val = val * cand + cc
                    if val == 0:
                        out.add(cand)
            return
        ni = primes[i]
        inv = modinv(mod % ni, ni)
        for r in roots_per[i]:
            t = (r - cur) * inv % ni
            dfs(i + 1, cur + t * mod, mod * ni)

    dfs(0, 0, 1)
    return sorted(out)


def small_roots(coeffs, n, beta, X, m=None, t=None):
    """
    Coppersmith 单变量小根 (Howgrave-Graham + LLL).
    求 f(x)=coeffs 的根 x0: |x0| < X 且 gcd(f(x0) mod n, n) >= n^beta.
    典型用途: 已知 p 高位比特分解 n (f(x)=p_high<<s + x, beta=0.5).
    要求 f 首一 (最高次系数为 1). m, t: 格参数. 返回整数根列表.

    注意: f^i 的系数必须是精确整数 (不能 mod n), 否则 mod p^m 整除性被破坏.
    """
    f = poly_trim([c % n for c in coeffs])
    delta = len(f) - 1
    assert delta >= 1, "need degree >= 1"
    assert f[-1] == 1, "f must be monic (首一)"
    if m is None:
        m = max(3, int(0.5 * beta * beta * n.bit_length() / max(1, X.bit_length())))
    if t is None:
        t = m
    X = int(X)
    w = delta * m + t
    # f^i 的整数系数 (不取模!)
    fpow = [[1]]
    for _ in range(m):
        fpow.append(poly_mul(fpow[-1], f))
    rows = []
    for i in range(m):
        for j in range(delta):
            row = [0] * w
            for k, c in enumerate(fpow[i]):
                pos = k + j
                if pos < w:
                    row[pos] = c * n ** (m - i)
            rows.append([c * X ** k for k, c in enumerate(row)])
    fm = fpow[m]
    for i in range(t):
        row = [0] * w
        for k, c in enumerate(fm):
            pos = k + i
            if pos < w:
                row[pos] = c
        rows.append([c * X ** k for k, c in enumerate(row)])

    B = lll(rows)
    roots = set()
    for vec in B:
        cfs = []
        ok = True
        for k in range(w):
            v = vec[k]
            if v % X ** k:
                ok = False
                break
            cfs.append(v // X ** k)
        if not ok:
            continue
        cfs = poly_trim(cfs)
        if not cfs or len(cfs) < 2:
            continue
        for r in _int_roots_mod(cfs, X):
            if abs(r) < X and math.gcd(poly_eval(f, r, n) % n, n) >= n ** beta:
                roots.add(r)
    return sorted(roots)


def solve_hnp(samples, p, B):
    """
    隐数问题 (Hidden Number Problem) 格解法.
    samples: [(a_i, c_i)] 满足  a_i*x - e_i ≡ c_i (mod p),  |e_i| < B.
    返回恢复的 x (或 None).

    格构造: 短向量 v = (K*x, w*(a_i*x - c_i - k_i*p), -W) = (K*x, w*e_i, -W)
    其中 r0 行携带 (K, w*a_1..w*a_n), p-行提供模约简, 目标行嵌入 CVP.
    """
    n = len(samples)
    w = max(1, p // (2 * B))
    K = max(1, (2 * B * w) // p)  # x 坐标权重, 平衡 K*x 与 w*e 的数量级
    dim = n + 2
    rows = []
    # r0 = (K, w*a_1, ..., w*a_n, 0) — a_i 必须带 w 权重保持坐标尺度一致
    r0 = [0] * dim
    r0[0] = K
    for i, (a, c) in enumerate(samples):
        r0[1 + i] = w * (int(a) % p)
    rows.append(r0)
    # p 行: (0, ..., w*p at i+1, ..., 0)
    for i in range(n):
        row = [0] * dim
        row[1 + i] = w * p
        rows.append(row)
    # 目标行: (0, w*c_1, ..., w*c_n, W)
    trow = [0] * dim
    for i, (a, c) in enumerate(samples):
        trow[1 + i] = w * (int(c) % p)
    trow[dim - 1] = 2 * B * w
    rows.append(trow)
    for v in lll(rows):
        for x0 in (v[0] // K if v[0] % K == 0 else None, -(v[0] // K) if v[0] % K == 0 else None):
            if x0 is None:
                continue
            cand = x0 % p
            if cand == 0:
                continue
            ok = True
            for a, c in samples:
                e = (a * cand - c) % p
                if e > p // 2:
                    e -= p
                if abs(e) >= B:
                    ok = False
                    break
            if ok:
                return cand
    return None


def solve_lcg_params(outputs):
    """由 >=6 个连续完整输出恢复 LCG (m, a, c). 返回 (m, a, c) 或 None"""
    x = list(outputs)
    d = [x[i + 1] - x[i] for i in range(len(x) - 1)]
    m = 0
    for i in range(len(d) - 2):
        m = math.gcd(m, abs(d[i + 2] * d[i] - d[i + 1] ** 2))
    if m == 0:
        return None
    try:
        a = (x[2] - x[1]) * modinv(x[1] - x[0], m) % m
        c = (x[1] - a * x[0]) % m
    except ValueError:
        return None
    if all((a * x[i] + c) % m == x[i + 1] for i in range(len(x) - 1)):
        return m, a, c
    return None


def solve_lcg_truncated(m, a, c, highs, shift):
    """
    已知 LCG 参数 (m,a,c) 与各输出的高比特 highs[i], 低 shift 位未知.
    返回恢复的完整状态列表 [s_0..s_{n-1}] 或 None.
    """
    n = len(highs)
    # l_{i+1} ≡ a*l_i + (a*h_i - h_{i+1})*2^shift + c   (mod m)
    cs = [((a * highs[i] - highs[i + 1]) * (1 << shift) + c) % m for i in range(n - 1)]
    # 特解: d_{i+1} = a*d_i + c_i
    d = [0]
    for ci in cs:
        d.append((a * d[-1] + ci) % m)
    # l_i = a^i*l_0 + d_i (mod m), 要求 0 <= l_i < 2^shift
    # 格基 (n 行): v0 与 m*e_j (j>=1); m*e_0 方向由 v0 的自由系数提供
    rows = [[pow(a, i, m) for i in range(n)]]
    for j in range(1, n):
        row = [0] * n
        row[j] = m
        rows.append(row)
    center = 1 << (shift - 1)
    target = [center - di for di in d]
    L = babai(rows, target)
    states = [highs[i] * (1 << shift) + (d[i] + L[i]) % m for i in range(n)]
    for i in range(n - 1):
        if (a * states[i] + c) % m != states[i + 1] % m:
            return None
    if any(not (0 <= (states[i] - highs[i] * (1 << shift)) < (1 << shift)) for i in range(n)):
        return None
    return states


# ======================================================================
# PRNG: MT19937 / LCG
# ======================================================================

class MT19937:
    """标准 MT19937 (32 位输出)"""

    N, M = 624, 397
    MATRIX_A = 0x9908B0DF
    UPPER, LOWER = 0x80000000, 0x7FFFFFFF

    def __init__(self, seed=0):
        self.mt = [0] * self.N
        self.idx = self.N
        self.seed_mt(seed)

    def seed_mt(self, seed):
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, self.N):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
        self.idx = self.N

    def set_state(self, state):
        assert len(state) == self.N
        self.mt = list(state)
        self.idx = self.N

    def twist(self):
        for i in range(self.N):
            y = (self.mt[i] & self.UPPER) | (self.mt[(i + 1) % self.N] & self.LOWER)
            nxt = self.mt[(i + self.M) % self.N] ^ (y >> 1)
            if y & 1:
                nxt ^= self.MATRIX_A
            self.mt[i] = nxt & 0xFFFFFFFF
        self.idx = 0

    def next32(self):
        if self.idx >= self.N:
            self.twist()
        y = self.mt[self.idx]
        self.idx += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def next_bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self.next32().to_bytes(4, "big")
        return bytes(out[:n])


def _inv_shift_right(x, s):
    res = x
    for _ in range(32 // s + 1):
        res = x ^ (res >> s)
    return res & 0xFFFFFFFF


def _inv_shift_left(x, s, mask):
    res = x
    for _ in range(32 // s + 1):
        res = x ^ ((res << s) & mask & 0xFFFFFFFF)
    return res & 0xFFFFFFFF


def untemper(y):
    """MT19937 temper 的逆变换"""
    y = _inv_shift_right(y, 18)
    y = _inv_shift_left(y, 15, 0xEFC60000)
    y = _inv_shift_left(y, 7, 0x9D2C5680)
    y = _inv_shift_right(y, 11)
    return y


def clone_mt(outputs):
    """由 >=624 个连续输出克隆 MT19937 (可继续预测后续输出)"""
    assert len(outputs) >= 624
    m = MT19937()
    m.set_state([untemper(y) for y in outputs[:624]])
    return m


class LCG:
    def __init__(self, a, c, m, seed):
        self.a, self.c, self.m, self.s = a, c, m, seed

    def next(self):
        self.s = (self.a * self.s + self.c) % self.m
        return self.s


# ======================================================================
# 对称密码辅助
# ======================================================================

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data, block=16):
    if not data or len(data) % block:
        raise ValueError("bad length")
    n = data[-1]
    if not 1 <= n <= block or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def pkcs7_valid(data, block=16):
    try:
        pkcs7_unpad(data, block)
        return True
    except ValueError:
        return False


def evp_bytes_to_key(password, salt, key_len):
    """OpenSSL 传统 KDF (EVP_BytesToKey, MD5): 派生密钥流 (传统 PEM 加密用)."""
    out = b""
    prev = b""
    while len(out) < key_len:
        h = hashlib.md5()
        h.update(prev + password + salt)
        prev = h.digest()
        out += prev
    return out[:key_len]


def pem_decrypt(pem_text, password):
    """
    解密传统加密 PEM 私钥 (Proc-Type: 4,ENCRYPTED).
    支持 DEK-Info: DES-EDE3-CBC (旧 OpenSSH) 与 AES-128-CBC (新 OpenSSH 的
    传统 PEM 模式, EVP_BytesToKey(MD5) 派生 16 字节密钥).
    返回解密后的 PEM 文本 (-----BEGIN ... PRIVATE KEY-----).
    """
    import base64 as _b64
    lines = pem_text.strip().splitlines()
    header = lines[0].strip()
    proc = dek = None
    b64 = []
    for ln in lines[1:]:
        s = ln.strip()
        if s.startswith("Proc-Type:"):
            proc = s
        elif s.startswith("DEK-Info:"):
            dek = s
        elif s.startswith("-----"):
            break
        else:
            b64.append(s)
    assert proc and "ENCRYPTED" in proc, "not an encrypted PEM"
    assert dek, "missing DEK-Info"
    algo, _, hexsalt = dek.split(":", 1)[1].strip().partition(",")
    salt = bytes.fromhex(hexsalt.strip())
    from Crypto.Cipher import DES3, AES
    if algo == "DES-EDE3-CBC":
        key, iv, block = evp_bytes_to_key(password, salt, 24), salt, 8
    elif algo == "AES-128-CBC":
        key, iv, block = evp_bytes_to_key(password, salt, 16), salt, 16
    else:
        raise ValueError(f"unsupported PEM cipher: {algo}")
    cipher = DES3.new(key, DES3.MODE_CBC, iv) if algo == "DES-EDE3-CBC" \
        else AES.new(key, AES.MODE_CBC, iv)
    der = cipher.decrypt(_b64.b64decode("".join(b64)))
    der = der[:-der[-1]]  # PKCS 去填充
    body = _b64.encodebytes(der).decode().replace("\n", "")
    end_line = header.replace("BEGIN", "END")
    return f"{header}\n{body}\n{end_line}\n"


# ======================================================================
# 古典密码与英文评分
# ======================================================================

ENGLISH_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}


def chi2_english(text):
    """卡方评分 (越低越像英文); 只统计字母"""
    cnt = {c: 0 for c in ENGLISH_FREQ}
    total = 0
    for ch in text:
        c = ch.lower()
        if c in cnt:
            cnt[c] += 1
            total += 1
    if total == 0:
        return float("inf")
    return sum((cnt[c] - total * f / 100) ** 2 / max(total * f / 100, 0.5)
               for c, f in ENGLISH_FREQ.items())


class BigramModel:
    """由语料构建的 bigram 对数概率模型 (替代密码爬山等)"""

    def __init__(self, corpus_path=None):
        path = corpus_path or os.path.join(_DATA, "corpus_en.txt")
        try:
            text = open(path, encoding="utf-8", errors="ignore").read().lower()
        except OSError:
            text = "the quick brown fox jumps over the lazy dog " * 200
        counts = {}
        for i in range(len(text) - 1):
            k = text[i: i + 2]
            counts[k] = counts.get(k, 0) + 1
        total = max(1, len(text) - 1)
        self.logp = {k: math.log(v / total) for k, v in counts.items()}
        self.floor = math.log(0.01 / total)

    def score(self, text):
        s, lp, fl = 0.0, self.logp, self.floor
        for i in range(len(text) - 1):
            s += lp.get(text[i: i + 2].lower(), fl)
        return s / max(1, len(text) - 1)


def caesar_shift(text, k):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text, key, decrypt=False):
    key = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            k = key[ki % len(key)]
            if decrypt:
                k = -k
            out.append(chr((ord(ch) - base + k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def affine_decrypt(text, a, b):
    ainv = modinv(a, 26)
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ainv * (ord(ch) - 97 - b) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr(ainv * (ord(ch) - 65 - b) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


class Playfair:
    def __init__(self, key):
        alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J 并入 I
        seen = []
        for ch in key.upper():
            if ch in alpha and ch not in seen:
                seen.append(ch)
        for ch in alpha:
            if ch not in seen:
                seen.append(ch)
        self.sq = [seen[i * 5: i * 5 + 5] for i in range(5)]
        self.pos = {ch: (i, j) for i, row in enumerate(self.sq) for j, ch in enumerate(row)}

    def _prep(self, text):
        text = text.upper().replace("J", "I")
        text = "".join(c for c in text if c in self.pos)
        out, i = [], 0
        while i < len(text):
            a = text[i]
            b = text[i + 1] if i + 1 < len(text) else "X"
            if a == b:
                out.extend((a, "X"))
                i += 1
            else:
                out.extend((a, b))
                i += 2
        if len(out) % 2:
            out.append("X")
        return out

    def encrypt(self, text):
        pp = self._prep(text)
        out = []
        for i in range(0, len(pp), 2):
            out.extend(self._pair(pp[i], pp[i + 1], 1))
        return "".join(out)

    def decrypt(self, text):
        text = "".join(c for c in text.upper() if c in self.pos)
        out = []
        for i in range(0, len(text) - 1, 2):
            out.extend(self._pair(text[i], text[i + 1], -1))
        return "".join(out)

    def _pair(self, a, b, direction):
        (r1, c1), (r2, c2) = self.pos[a], self.pos[b]
        if r1 == r2:
            return [self.sq[r1][(c1 + direction) % 5], self.sq[r2][(c2 + direction) % 5]]
        if c1 == c2:
            return [self.sq[(r1 + direction) % 5][c1], self.sq[(r2 + direction) % 5][c2]]
        return [self.sq[r1][c2], self.sq[r2][c1]]


def mat_mul_mod(A, B, n):
    return [[sum(A[i][t] * B[t][j] for t in range(len(B))) % n
             for j in range(len(B[0]))] for i in range(len(A))]


def hill_key_from_knownpt(pt_blocks, ct_blocks, n=26):
    """
    已知明密文块恢复 Hill 密钥 K: 满足 ct_block = pt_block * K (mod n).
    块为长度 k 的列表; 需要至少 k 块. 返回 k x k 矩阵或 None.
    """
    k = len(pt_blocks[0])
    if len(pt_blocks) < k:
        return None
    key_cols = []
    for j in range(k):
        # 方程: sum_i pt[b][i] * K[i][j] = ct[b][j]
        aug = [[pt_blocks[b][i] for i in range(k)] + [ct_blocks[b][j] % n]
               for b in range(k)]
        x = _lin_solve_mod(aug, k, n)
        if x is None:
            return None
        key_cols.append(x)
    return [[key_cols[j][i] % n for j in range(k)] for i in range(k)]


def _lin_solve_mod(aug, k, n):
    """解 k 元模 n 线性方程组 (增广矩阵 k x (k+1)). 返回解列表或 None."""
    M = [row[:] for row in aug]
    piv_rows = []
    for col in range(k):
        piv = None
        used = {r for _, r in piv_rows}
        for r in range(k):
            if r not in used and math.gcd(M[r][col], n) == 1:
                piv = r
                break
        if piv is None:
            return None
        piv_rows.append((col, piv))
        inv = modinv(M[piv][col], n)
        M[piv] = [x * inv % n for x in M[piv]]
        for r in range(k):
            if r != piv and M[r][col] % n:
                f = M[r][col]
                M[r] = [(x - f * y) % n for x, y in zip(M[r], M[piv])]
    sol = [0] * k
    for col, r in piv_rows:
        sol[col] = M[r][k] % n
    return sol


# ======================================================================
# 哈希: 纯 Python MD5 (支持长度扩展) + CRC32
# ======================================================================

_MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
_MD5_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]


def md5_compress(state, block):
    """MD5 压缩函数: state=(a,b,c,d), block=64 字节. 返回新 state."""
    a, b, c, d = state
    M = struct.unpack("<16I", block)
    A, B_, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            F = (B_ & C) | (~B_ & D)
            g = i
        elif i < 32:
            F = (D & B_) | (~D & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            F = B_ ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            F = C ^ (B_ | (~D & 0xFFFFFFFF))
            g = (7 * i) % 16
        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        # (a,b,c,d) <- (d, b + rotl(F,s), b, c)
        A, B_, C, D = D, (B_ + ((F << _MD5_S[i]) | (F >> (32 - _MD5_S[i])))) & 0xFFFFFFFF, B_, C
    return ((a + A) & 0xFFFFFFFF, (b + B_) & 0xFFFFFFFF,
            (c + C) & 0xFFFFFFFF, (d + D) & 0xFFFFFFFF)


def md5_pad(msg_len):
    """MD5 填充 (按给定消息长度计算)"""
    return (b"\x80" + b"\x00" * ((55 - msg_len) % 64)
            + struct.pack("<Q", (msg_len * 8) & 0xFFFFFFFFFFFFFFFF))


def md5(msg):
    """纯 Python MD5 (与 hashlib 结果一致)"""
    st = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    padded = msg + md5_pad(len(msg))
    for i in range(0, len(padded), 64):
        st = md5_compress(st, padded[i: i + 64])
    return struct.pack("<4I", *st)


def md5_lenext(digest, prefix_len, suffix):
    """
    MD5 长度扩展攻击核心.
    已知 md5(secret || msg) = digest 且 |secret+msg| = prefix_len (secret
    未知时由调用方爆破其长度). 返回 (appendix, new_digest):
        md5(secret + msg + appendix) == new_digest
    其中 appendix = 原始消息的 glue padding + suffix.
    """
    state = struct.unpack("<4I", digest)
    glue = md5_pad(prefix_len)
    # 重新压缩: suffix 之后接「总长 = prefix_len+len(glue)+len(suffix)」的填充
    padded = suffix + md5_pad(prefix_len + len(glue) + len(suffix))
    st = state
    for i in range(0, len(padded), 64):
        st = md5_compress(st, padded[i: i + 64])
    return glue + suffix, struct.pack("<4I", *st)


def gf2_solve(matrix, rhs, size=32):
    """
    GF(2) 线性方程组求解. matrix: size x size 0/1 矩阵 (行), rhs: 长度 size.
    返回解 (0/1 列表) 或 None (无解).
    """
    M = [(matrix[i][:], rhs[i]) for i in range(size)]
    piv_row = 0
    piv_col_of = {}
    for col in range(size):
        r = None
        for i in range(piv_row, size):
            if M[i][0][col]:
                r = i
                break
        if r is None:
            continue
        M[piv_row], M[r] = M[r], M[piv_row]
        for i in range(size):
            if i != piv_row and M[i][0][col]:
                M[i] = ([a ^ b for a, b in zip(M[i][0], M[piv_row][0])],
                        M[i][1] ^ M[piv_row][1])
        piv_col_of[col] = piv_row
        piv_row += 1
    for i in range(piv_row, size):
        if not any(M[i][0]) and M[i][1]:
            return None
    sol = [0] * size
    for col in range(size):
        if col in piv_col_of:
            sol[col] = M[piv_col_of[col]][1]
    return sol


def crc32_patch(prefix, target, nbytes=4):
    """
    返回 nbytes 字节后缀 s, 使 crc32(prefix + s) == target.
    利用 CRC32 对输入比特的 GF(2) 线性性解线性方程组.
    """
    base = zlib.crc32(prefix)
    f0 = zlib.crc32(b"\x00" * nbytes, base)
    cols = []
    for bit in range(nbytes * 8):
        probe = bytearray(nbytes)
        probe[bit // 8] |= 1 << (7 - bit % 8)
        delta = zlib.crc32(bytes(probe), base) ^ f0
        cols.append([(delta >> (31 - i)) & 1 for i in range(32)])
    matrix = [[cols[bit][row] for bit in range(nbytes * 8)] for row in range(32)]
    rhs = [((f0 ^ target) >> (31 - i)) & 1 for i in range(32)]
    sol = gf2_solve(matrix, rhs, 32)
    if sol is None:
        return None
    out = bytearray(nbytes)
    for bit in range(nbytes * 8):
        if sol[bit]:
            out[bit // 8] |= 1 << (7 - bit % 8)
    return bytes(out)


# ======================================================================
# 编码识别
# ======================================================================

def try_decode_layers(data, max_layers=8):
    """
    自动剥离 hex / base32 / base64 / ascii85 / url / reverse 嵌套编码.
    返回 (最内层数据 bytes, 剥离的层级名称列表).
    """
    layers = []
    cur = data if isinstance(data, bytes) else data.encode()
    for _ in range(max_layers):
        try:
            s = cur.decode("ascii").strip()
        except (UnicodeDecodeError, AttributeError):
            break
        if not s:
            break
        decoded, name = None, None
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
            decoded, name = bytes.fromhex(s), "hex"
        else:
            for pat, fn, nm in (
                (r"[A-Z2-7]+={0,6}", base64.b32decode, "base32"),
                (r"[A-Za-z0-9+/]+={0,2}", base64.b64decode, "base64"),
                (r"[!-u]+", base64.a85decode, "ascii85"),
            ):
                if re.fullmatch(pat, s) and len(s) >= 8:
                    try:
                        cand = fn(s)
                        # 合理的解码结果应含可打印内容或非空
                        if cand:
                            decoded, name = cand, nm
                            break
                    except Exception:
                        continue
        if decoded is None:
            from urllib.parse import unquote
            if "%" in s:
                try:
                    decoded = unquote(s).encode()
                    name = "url"
                except Exception:
                    break
                else:
                    cur = decoded
                    layers.append(name)
                    continue
            break
        cur = decoded
        layers.append(name)
    return cur, layers
