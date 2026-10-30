# -*- coding: utf-8 -*-
"""ctfk 工具库单元测试: python tools/test_ctfk.py"""
import os
import random
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
import hashlib  # noqa: E402

import ctfk as K  # noqa: E402

rng = random.Random(20261025)
FAILS = []


def check(name, cond, extra=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name} {extra}")
    if not cond:
        FAILS.append(name)


# ---------- 数与字节 ----------
check("b2l/l2b roundtrip", K.l2b(K.b2l(b"\x00flag{ok}")) == b"flag{ok}")
check("iroot cube", K.iroot(12345 ** 3, 3) == 12345 and K.iroot(12345 ** 3 - 1, 3) == 12344)
check("iroot big", K.iroot(K.b2l(b"A" * 32) ** 3, 3) == K.b2l(b"A" * 32))
check("crt", K.crt([(2, 3), (3, 5), (2, 7)])[0] == 23)
check("xor cycle", K.xor_bytes(b"abcd", b"\x00") == b"abcd")
check("hamming", K.hamming_bits(b"this is a test", "wokka wokka!!!".encode()) == 37)

# ---------- 素数 ----------
check("is_prime", K.is_prime(2 ** 61 - 1) and not K.is_prime(2 ** 61 - 3))
n80 = 317 * 709 * 1103 * 2417  # 4个素数
check("factorint", set(K.factorint(n80).items()) == {(317, 1), (709, 1), (1103, 1), (2417, 1)})
p40 = K.randprime(40, rng)
check("randprime", K.is_prime(p40) and p40.bit_length() == 40)

# ---------- Wiener / Fermat ----------
p = K.randprime(256, rng)
q = K.randprime(256, rng)
n = p * q
d = K.randprime(250, rng)  # < n^0.25/3 (512bit -> ~128bit 限制, 250bit 太大!)
d = rng.getrandbits(120) | 1
e = K.modinv(d, (p - 1) * (q - 1))
dw = K.wiener(e, n)
check("wiener", dw == d, f"got {dw}")

pp = K.randprime(200, rng)
qq = pp + 2 * rng.getrandbits(8)
if not K.is_prime(qq):
    qq = pp + 2
    while not K.is_prime(qq):
        qq += 2
r = K.fermat_factor(pp * qq)
check("fermat", r and set(r) == {pp, qq})

# ---------- DLOG ----------
p_s, g_s, x_s = 10007, 5, 4321
check("bsgs", K.bsgs(g_s, pow(g_s, x_s, p_s), p_s, order=p_s - 1) == x_s)

# pohlig: 选 p-1 光滑的素数
for cand in range(100003, 200000, 2):
    if K.is_prime(cand):
        f = K.factorint(cand - 1)
        if max(q ** e for q, e in f.items()) < 2 ** 16:
            p_s2 = cand
            break
g2 = 3
order2 = p_s2 - 1
x2 = 98765
h2 = pow(g2, x2, p_s2)
got = K.pohlig_hellman(g2, h2, p_s2, f)
check("pohlig_hellman", got is not None and pow(g2, got, p_s2) == h2, f"p={p_s2}")

# ---------- 椭圆曲线 ----------
# 小曲线测试: y^2 = x^3 + 2x + 2 mod 17 (order 19, 生成元 (5,1))
E = K.EC(2, 2, 17)
G = (5, 1)
pts = [None]
P = G
while P is not None and len(pts) < 25:
    pts.append(P)
    P = E.add(P, G)
check("ec add/cycle", len(pts) == 19, f"order={len(pts)}")
Q = E.mul(7, G)
check("ec_bsgs", E.ec_bsgs(G, Q, 19) == 7)
# supersingular 光滑阶曲线: p ≡ 2 (mod 3) 保证 y^2=x^3+1 阶为 p+1;
# p ≡ 3 (mod 4) 保证 (p+1)/4 整数开方可用 → p ≡ 11 (mod 12)
for cand in range(2 ** 20, 2 ** 22):
    if cand % 12 == 11 and K.is_prime(cand):
        f = K.factorint(cand + 1)
        if max(q ** e for q, e in f.items()) < 2 ** 12:
            pp_ec = cand
            break
E2 = K.EC(0, 1, pp_ec)
# 找生成元
G2 = None
for x in range(1, 50):
    rhs = (x ** 3 + 1) % pp_ec
    y = pow(rhs, (pp_ec + 1) // 4, pp_ec)
    if y * y % pp_ec == rhs:
        G2 = (x, y)
        break
N2 = pp_ec + 1
# 求 G2 的真实阶: 最小 d 使 d*G2 = None
ord2 = None
acc = None
for d in range(1, N2 + 1):
    acc = E2.add(acc, G2)
    if acc is None:
        ord2 = d
        break
f_ord2 = K.factorint(ord2)
ok_all = True
for trial in range(10):  # 随机标量回归 (覆盖素数幂 e>=2 的数字位)
    k2 = rng.randrange(1, ord2)
    Q2 = E2.mul(k2, G2)
    got2 = E2.ec_pohlig(G2, Q2, f_ord2)
    if got2 is None or got2 % ord2 != k2 % ord2:
        ok_all = False
        break
check("ec_pohlig (random scalars)", ok_all, f"p={pp_ec} ord={ord2} factors={f_ord2}")

# ---------- LLL / knapsack (CJLOSS 构造) ----------
weights = []
s = 0
for i in range(16):
    w = s + rng.randint(1, 50)
    weights.append(w)
    s += w
Mk = s * 2 + rng.randint(1, 100)
r_ = rng.randrange(2, Mk) + 1
import math as _m
while _m.gcd(r_, Mk) != 1:
    r_ += 1
pub = [w * r_ % Mk for w in weights]
msg_bits = [rng.randint(0, 1) for _ in range(16)]
csum = sum(b * p_ for b, p_ in zip(msg_bits, pub))
Bm = []
for i in range(16):
    row = [0] * 17
    row[i] = 2
    row[16] = 2 * pub[i]
    Bm.append(row)
last = [1] * 16 + [2 * csum]
Bm.append(last)
red = K.lll(Bm)
found = None
for vec in red:
    if vec[16] != 0:
        continue
    v = vec[:16]
    if all(x in (-1, 1) for x in v):
        bits = [1 if x == 1 else 0 for x in v]
        if sum(b * p_ for b, p_ in zip(bits, pub)) == csum:
            found = bits
            break
        bits = [1 if x == -1 else 0 for x in v]
        if sum(b * p_ for b, p_ in zip(bits, pub)) == csum:
            found = bits
            break
check("lll knapsack (CJLOSS)", found is not None and found == msg_bits)

# ---------- Coppersmith ----------
p_c = K.randprime(160, rng)
q_c = K.randprime(160, rng)
n_c = p_c * q_c
s_c = 48  # 未知低 48 位 → X = 2^48, 泄漏 112/160 位
high = p_c >> s_c
x0 = p_c - (high << s_c)
# 多项式应为 f(x) = (high << s) + x, 使得 f(x0) = p
roots = K.small_roots([high << s_c, 1], n_c, 0.5, 1 << s_c, m=3, t=3)
check("coppersmith high-p", x0 in roots, f"roots={roots[:3]}")

# ---------- HNP ----------
p_h = K.randprime(256, rng)
x_h = rng.randrange(p_h)
samples = []
B_h = 1 << 224  # 泄漏高 32 位 → 未知低 224 位
for _ in range(14):
    a = rng.randrange(1, p_h)
    b_rand = rng.randrange(p_h)
    v = (a * x_h + b_rand) % p_h
    leak = v >> 224
    c_i = (leak * (1 << 224) - b_rand) % p_h
    samples.append((a, c_i))
x_rec = K.solve_hnp(samples, p_h, B_h)
check("solve_hnp", x_rec == x_h, f"got {x_rec}")

# ---------- LCG ----------
m_l = 2 ** 64 - 59
a_l = 6364136223846793005
c_l = 1442695040888963407
lcg = K.LCG(a_l, c_l, m_l, 123456789)
outs = [lcg.next() for _ in range(8)]
gotl = K.solve_lcg_params(outs)
check("lcg params", gotl == (m_l, a_l, c_l))

m_t = 2 ** 64 - 59
a_t, c_t = 6364136223846793005, 1442695040888963407
lg2 = K.LCG(a_t, c_t, m_t, 987654321)
outs_t = [lg2.next() for _ in range(12)]
highs = [o >> 32 for o in outs_t]
rec = K.solve_lcg_truncated(m_t, a_t, c_t, highs, 32)
check("lcg truncated", rec is not None and rec[0] == outs_t[0], f"got {rec[:2] if rec else None}")

# ---------- MT19937 ----------
mt = K.MT19937(31337)
outs_m = [mt.next32() for _ in range(624)]
rest = [mt.next32() for _ in range(20)]
mt2 = K.clone_mt(outs_m)
pred = [mt2.next32() for _ in range(20)]
check("mt19937 clone", pred == rest)

# ---------- rc4 / pkcs7 ----------
k_rc = b"secret-key"
data = b"attack at dawn" * 5
ct = K.rc4(k_rc, data)
check("rc4", K.rc4(k_rc, ct) == data)
check("pkcs7", K.pkcs7_unpad(K.pkcs7_pad(b"abc")) == b"abc")
check("pkcs7 valid", K.pkcs7_valid(K.pkcs7_pad(b"abc")) and not K.pkcs7_valid(b"abc\x01\x02"))

# ---------- 古典 ----------
check("caesar", K.caesar_shift("abc", 1) == "bcd" and K.caesar_shift("bcd", -1) == "abc")
check("vigenere rt", K.vigenere(K.vigenere("hello world", "key"), "key", decrypt=True) == "hello world")
pt = "the quick brown fox jumps over the lazy dog"
ct_a = "".join(chr((5 * (ord(c) - 97) + 8) % 26 + 97) if "a" <= c <= "z" else c for c in pt)
check("affine dec", K.affine_decrypt(ct_a, 5, 8) == pt)

pf = K.Playfair("monarchy")
check("playfair rt", pf.decrypt(pf.encrypt("hidethegoldinthetreestump")).startswith("HIDETHEGOLD"))

# hill 已知明文恢复 (明文块矩阵需可逆 mod 26)
kk = [[3, 5], [1, 2]]
pts_h = [[7, 8], [3, 5], [1, 1], [0, 3]]
cts_h = [K.mat_mul_mod([p], kk, 26)[0] for p in pts_h]
K_rec = K.hill_key_from_knownpt(pts_h, cts_h)
check("hill knownpt", K_rec is not None and K.mat_mul_mod([pts_h[0]], K_rec, 26)[0] == cts_h[0]
      and K.mat_mul_mod([pts_h[3]], K_rec, 26)[0] == cts_h[3])

# ---------- MD5 ----------
for msg in [b"", b"a", b"hello world" * 10, bytes(rng.randrange(256) for _ in range(200))]:
    if K.md5(msg) != hashlib.md5(msg).digest():
        check("md5 vs hashlib", False, f"msg len {len(msg)}")
        break
else:
    check("md5 vs hashlib", True)

# 长度扩展
secret = b"top-secret-key"
msg = b"count=10"
dg = hashlib.md5(secret + msg).digest()
suffix = b";admin=true"
ok = False
for L in range(1, 40):
    appendix, ndg = K.md5_lenext(dg, L + len(msg), suffix)
    if hashlib.md5(secret + msg + appendix).digest() == ndg:
        ok = True
        break
check("md5 lenext", ok)

# ---------- CRC32 ----------
prefix = b"ACCESS DENIED: user guest\n"
target = zlib.crc32(b"some other content entirely")
patch = K.crc32_patch(prefix, target)
check("crc32 patch", patch is not None and zlib.crc32(prefix + patch) == target)

# ---------- poly gcd (Franklin-Reiter 组件) ----------
n_p = p * q
m1 = K.b2l(b"message one!!")
c1 = pow(m1, 3, n_p)
c2 = pow(m1 + 1, 3, n_p)
# gcd(x^3 - c1, (x+1)^3 - c2) mod n → 线性多项式 x + a, 其根即 m1
g_poly, fac = K.poly_gcd_modn(
    [(-c1) % n_p, 0, 0, 1],
    [(1 - c2) % n_p, 3, 3, 1],
    n_p,
)
check("poly gcd franklin", fac is None and len(g_poly) == 2 and
      (-g_poly[0] * K.modinv(g_poly[1], n_p)) % n_p == m1 % n_p)

# ---------- 评分 ----------
bm = K.BigramModel()
check("bigram model", bm.score("the quick brown fox") > bm.score("xq zz jj vv pp"))

print()
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL TESTS PASSED")
