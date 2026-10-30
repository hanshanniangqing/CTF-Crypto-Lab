# -*- coding: utf-8 -*-
"""RSA 分类出题脚本 (共 11 题): rsa-baby, rsa-common-modulus, rsa-broadcast,
rsa-small-e, rsa-shared-prime, rsa-fermat, rsa-wiener, rsa-lsb-oracle,
rsa-franklin-reiter, rsa-coppersmith, rsa-sign-forgery"""
from build_common import *

from Crypto.Util.number import bytes_to_long, long_to_bytes


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


# ---------------------------------------------------------------- 示范题
@register("rsa-common-modulus")
def gen_rsa_common_modulus(ch):
    flag = ch["flag"]
    rng = rng_for("rsa-common-modulus")
    p = ctfk.randprime(256, rng)
    q = ctfk.randprime(256, rng)
    n = p * q
    e1 = 65537
    e2 = 65539
    phi = (p - 1) * (q - 1)
    while ctfk.math.gcd(e2, phi) != 1 or ctfk.math.gcd(e1, e2) != 1:
        e2 += 2
    m = bytes_to_long(flag.encode())
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    txt = (
        "RSA common modulus: same message, same modulus, coprime exponents\n"
        f"n  = {n:x}\n"
        f"e1 = {e1:x}\n"
        f"e2 = {e2:x}\n"
        f"c1 = {c1:x}\n"
        f"c2 = {c2:x}\n"
    )
    write_src("rsa-common-modulus", "output.txt", txt)
    # 自检: 扩展欧几里得 + 共模公式恢复 m
    g, s1, s2 = egcd(e1, e2)
    mm = pow(c1, s1, n) * pow(c2, s2, n) % n
    verify("rsa-common-modulus", g == 1, "e1,e2 必须互素")
    verify("rsa-common-modulus", mm == m, "共模公式未恢复出明文")
    verify("rsa-common-modulus", ctfk.is_prime(p) and ctfk.is_prime(q), "素数生成异常")


# ======================================================================
# 以下: RSA 分类其余 10 题
# ======================================================================

def _keypair(rng, bits, e):
    """生成 (p, q, n, phi); gcd(e, phi) != 1 时在 rng 流内重摇 p,q (确定性)"""
    while True:
        p = ctfk.randprime(bits, rng)
        q = ctfk.randprime(bits, rng)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if ctfk.math.gcd(e, phi) == 1:
            return p, q, p * q, phi


# ---------------------------------------------------------------- rsa-baby
@register("rsa-baby")
def gen_rsa_baby(ch):
    rng = rng_for("rsa-baby")
    e = 65537
    p, q, n, phi = _keypair(rng, 40, e)
    body = b"f4ct0r_1t"
    m = bytes_to_long(body)
    c = pow(m, e, n)
    txt = (
        "RSA with a tiny 80-bit modulus. Have fun.\n"
        "(format: hex)\n"
        f"n = {n:x}\n"
        f"e = {e:x}\n"
        f"c = {c:x}\n"
    )
    write_src("rsa-baby", "output.txt", txt)
    d = ctfk.modinv(e, phi)
    verify("rsa-baby", m < n, "明文必须小于模数")
    verify("rsa-baby", pow(c, d, n) == m, "私钥解密未恢复明文")
    fac = ctfk.factorint(n)
    verify("rsa-baby", set(fac) == {p, q}, "factorint 应分解出 p,q")


# ---------------------------------------------------------------- rsa-small-e
@register("rsa-small-e")
def gen_rsa_small_e(ch):
    rng = rng_for("rsa-small-e")
    flag = ch["flag"]
    e = 3
    p, q, n, phi = _keypair(rng, 512, e)
    m = bytes_to_long(flag.encode())
    c = m ** 3  # 不取模: m^3 < n, 模运算根本没生效
    txt = (
        "Textbook RSA with e = 3 and no padding.\n"
        "(format: hex; note: c = m^3 over the integers)\n"
        f"n = {n:x}\n"
        f"e = {e:x}\n"
        f"c = {c:x}\n"
    )
    write_src("rsa-small-e", "output.txt", txt)
    verify("rsa-small-e", m ** 3 < n, "必须满足 m^3 < n (否则题面不成立)")
    verify("rsa-small-e", ctfk.iroot(c, e) == m and long_to_bytes(m) == flag.encode(),
           "整数立方根应精确恢复明文")
    verify("rsa-small-e", ctfk.math.gcd(e, phi) == 1, "e 与 phi 必须互素")


# ---------------------------------------------------------------- rsa-broadcast
@register("rsa-broadcast")
def gen_rsa_broadcast(ch):
    rng = rng_for("rsa-broadcast")
    flag = ch["flag"]
    e = 3
    m = bytes_to_long(flag.encode())
    keys = []  # (n, phi, c), 两两互素
    while len(keys) < 3:
        p, q, n, phi = _keypair(rng, 256, e)
        if any(ctfk.math.gcd(n, n0) != 1 for n0, _, _ in keys):
            continue
        keys.append((n, phi, pow(m, e, n)))
    lines = [
        "Hastad broadcast: the same message sent to 3 users, e = 3, no padding.",
        "(format: hex)",
    ]
    for i, (n, _, c) in enumerate(keys, 1):
        lines.append(f"n{i} = {n:x}")
        lines.append(f"c{i} = {c:x}")
    write_src("rsa-broadcast", "output.txt", "\n".join(lines) + "\n")
    merged, mod = ctfk.crt([(c, n) for n, _, c in keys])
    verify("rsa-broadcast", all(m < n for n, _, _ in keys), "明文必须小于每个 n_i")
    verify("rsa-broadcast", all(m ** 3 > n for n, _, _ in keys),
           "m^3 必须大于每个 n_i (密文回绕, 才构成真正的广播场景)")
    verify("rsa-broadcast", merged == m ** 3 and m ** 3 < mod,
           "CRT 合并结果必须精确等于 m^3")
    verify("rsa-broadcast", long_to_bytes(ctfk.iroot(merged, 3)) == flag.encode(),
           "CRT + 整数开立方未恢复 flag")


# ---------------------------------------------------------------- rsa-shared-prime
@register("rsa-shared-prime")
def gen_rsa_shared_prime(ch):
    rng = rng_for("rsa-shared-prime")
    flag = ch["flag"]
    e = 65537
    while True:
        p = ctfk.randprime(256, rng)
        q1 = ctfk.randprime(256, rng)
        q2 = ctfk.randprime(256, rng)
        if len({p, q1, q2}) != 3:
            continue
        phi1, phi2 = (p - 1) * (q1 - 1), (p - 1) * (q2 - 1)
        if ctfk.math.gcd(e, phi1) == 1 and ctfk.math.gcd(e, phi2) == 1:
            break
    n1, n2 = p * q1, p * q2
    m = bytes_to_long(flag.encode())
    c1 = pow(m, e, n1)
    txt = (
        "Two RSA moduli from the same (broken) key generator.\n"
        "(format: hex)\n"
        f"n1 = {n1:x}\n"
        f"n2 = {n2:x}\n"
        f"e  = {e:x}\n"
        f"c1 = {c1:x}\n"
    )
    write_src("rsa-shared-prime", "output.txt", txt)
    g = ctfk.math.gcd(n1, n2)
    verify("rsa-shared-prime", g == p and 1 < p < min(n1, n2), "gcd(n1,n2) 应为共享素数 p")
    d = ctfk.modinv(e, phi1)
    verify("rsa-shared-prime", pow(c1, d, n1) == m, "私钥解密未恢复明文")


# ---------------------------------------------------------------- rsa-fermat
@register("rsa-fermat")
def gen_rsa_fermat(ch):
    rng = rng_for("rsa-fermat")
    flag = ch["flag"]
    e = 65537
    while True:
        p = ctfk.randprime(256, rng)
        gap = rng.randrange(2 ** 14, 2 ** 16)
        q = p + gap
        if q % 2 == 0:
            q += 1
        while not ctfk.is_prime(q):
            q += 2
        phi = (p - 1) * (q - 1)
        if q != p and ctfk.math.gcd(e, phi) == 1:
            break
    n = p * q
    m = bytes_to_long(flag.encode())
    c = pow(m, e, n)
    txt = (
        "RSA whose two primes were generated in the same neighbourhood.\n"
        "(format: hex)\n"
        f"n = {n:x}\n"
        f"e = {e:x}\n"
        f"c = {c:x}\n"
    )
    write_src("rsa-fermat", "output.txt", txt)
    fp, fq = ctfk.fermat_factor(n)
    verify("rsa-fermat", fp is not None and {fp, fq} == {p, q}, "fermat_factor 应恢复 p,q")
    d = ctfk.modinv(e, (p - 1) * (q - 1))
    verify("rsa-fermat", pow(c, d, n) == m, "私钥解密未恢复明文")


# ---------------------------------------------------------------- rsa-wiener
@register("rsa-wiener")
def gen_rsa_wiener(ch):
    rng = rng_for("rsa-wiener")
    flag = ch["flag"]
    while True:
        p = ctfk.randprime(512, rng)
        q = ctfk.randprime(512, rng)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        d = rng.getrandbits(130) | 1  # 远小于 n^(1/4)/3
        if ctfk.math.gcd(d, phi) == 1:
            break
    n = p * q
    e = ctfk.modinv(d, phi)
    m = bytes_to_long(flag.encode())
    c = pow(m, e, n)
    txt = (
        "RSA tuned for fast decryption: the private exponent d got too small.\n"
        "(format: hex)\n"
        f"n = {n:x}\n"
        f"e = {e:x}\n"
        f"c = {c:x}\n"
    )
    write_src("rsa-wiener", "output.txt", txt)
    verify("rsa-wiener", 3 * d < ctfk.iroot(n, 4), "Wiener 前提 d < n^(1/4)/3 不满足")
    verify("rsa-wiener", ctfk.wiener(e, n) == d, "Wiener 攻击应恢复 d")
    verify("rsa-wiener", pow(c, d, n) == m, "私钥解密未恢复明文")


# ---------------------------------------------------------------- rsa-lsb-oracle
_LSB_SERVER = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rsa-lsb-oracle 解密服务 (line 协议).
#
# 用法: python server.py --port N    (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端立刻发送一行:  PUB n=<hex> e=<十进制> c=<hex>
#   客户端每次发送一行:            QUERY <hex 密文>
#   服务端回答一行:                该密文解密结果 (mod n) 的最低位, "0" 或 "1"
#   发送 QUIT 或断开连接结束本次会话。
import argparse
import socket
import sys

P = 0x{p:x}
Q = 0x{q:x}
C = 0x{c:x}
E = 65537
N = P * Q
D = pow(E, -1, (P - 1) * (Q - 1))


def handle(conn):
    conn.sendall(("PUB n=%x e=%d c=%x\n" % (N, E, C)).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "QUERY" and len(parts) > 1:
                try:
                    mm = pow(int(parts[1], 16), D, N)
                    conn.sendall(b"%d\n" % (mm & 1))
                except ValueError:
                    conn.sendall(b"ERR\n")
            elif parts[0].upper() in ("QUIT", "EXIT"):
                break
    except OSError:
        pass
    finally:
        try:
            rfile.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(4)
    port = srv.getsockname()[1]
    sys.stdout.write("READY %d\n" % port)
    sys.stdout.flush()
    try:
        while True:
            conn, _ = srv.accept()
            try:
                handle(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
'''


@register("rsa-lsb-oracle")
def gen_rsa_lsb_oracle(ch):
    rng = rng_for("rsa-lsb-oracle")
    flag = ch["flag"]
    e = 65537
    p, q, n, phi = _keypair(rng, 256, e)
    m = bytes_to_long(flag.encode())
    c = pow(m, e, n)
    d = ctfk.modinv(e, phi)
    write_src("rsa-lsb-oracle", "server.py", _LSB_SERVER.format(p=p, q=q, c=c))
    verify("rsa-lsb-oracle", m < n, "明文必须小于模数")
    verify("rsa-lsb-oracle", pow(c, d, n) == m, "私钥解密未恢复明文")
    # 本地模拟 LSB 奇偶二分 (不经网络): 预言机对 c'=(m*2^i)^e 的回答是
    # LSB(m*2^i mod n) = parity(floor(m*2^i/n)) (m*2^i 偶, n 奇)
    L = n.bit_length()
    a = 0
    for i in range(1, L + 1):
        a = 2 * a + ((m * pow(2, i, n)) % n & 1)
    rec = (a * n + (1 << L) - 1) >> L  # ceil(a*n / 2^L)
    verify("rsa-lsb-oracle", rec == m, "LSB 奇偶二分模拟未恢复明文")
    verify("rsa-lsb-oracle", 510 <= L <= 512, "模数应为 ~512 bit")


# ---------------------------------------------------------------- rsa-franklin-reiter
@register("rsa-franklin-reiter")
def gen_rsa_franklin_reiter(ch):
    rng = rng_for("rsa-franklin-reiter")
    flag = ch["flag"]
    e = 3
    p, q, n, phi = _keypair(rng, 256, e)
    m1 = bytes_to_long(flag.encode())
    m2 = m1 + 1
    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    txt = (
        "Franklin-Reiter: two related messages encrypted under e = 3.\n"
        "# m2 = m1 + 1 (the two plaintexts differ by exactly 1)\n"
        "(format: hex)\n"
        f"n  = {n:x}\n"
        f"e  = {e:x}\n"
        f"c1 = {c1:x}\n"
        f"c2 = {c2:x}\n"
    )
    write_src("rsa-franklin-reiter", "output.txt", txt)
    d = ctfk.modinv(e, phi)
    verify("rsa-franklin-reiter", pow(c1, d, n) == m1, "私钥解密未恢复明文")
    # 模拟解题全流程: gcd(x^3 - c1, (x+1)^3 - c2) mod n 应为一次多项式, 根即 m1
    g, fac = ctfk.poly_gcd_modn([(-c1) % n, 0, 0, 1], [(1 - c2) % n, 3, 3, 1], n)
    ok = fac is None and len(g) == 2 and (-g[0] * ctfk.modinv(g[1], n)) % n == m1
    verify("rsa-franklin-reiter", ok, "多项式 gcd 未恢复 m1")


# ---------------------------------------------------------------- rsa-coppersmith
@register("rsa-coppersmith")
def gen_rsa_coppersmith(ch):
    rng = rng_for("rsa-coppersmith")
    flag = ch["flag"]
    e = 65537
    leak_bits = 48  # p 的低 48 位未知
    p, q, n, phi = _keypair(rng, 160, e)
    p_high = p >> leak_bits
    m = bytes_to_long(flag.encode())
    c = pow(m, e, n)
    txt = (
        "RSA side-channel leak: the high bits of the prime p are known.\n"
        "# p_high = p >> 48, i.e. the low 48 bits of p are unknown\n"
        "(format: hex)\n"
        f"n       = {n:x}\n"
        f"e       = {e:x}\n"
        f"c       = {c:x}\n"
        f"p_high  = {p_high:x}\n"
    )
    write_src("rsa-coppersmith", "output.txt", txt)
    d = ctfk.modinv(e, phi)
    verify("rsa-coppersmith", m < n, "明文必须小于模数")
    verify("rsa-coppersmith", pow(c, d, n) == m, "私钥解密未恢复明文")
    # beta 取 0.49 而非 0.5: small_roots 以 gcd(f(x0),n) >= n^beta 过滤根,
    # 泄露的素数可能是两因子中较小的一个 (< sqrt(n)), 0.5 会误杀真根;
    # 0.49 对 320-bit n 恒能放行 (p >= 2^159 > n^0.49 <= 2^157).
    roots = ctfk.small_roots([p_high << leak_bits, 1], n, 0.49, 1 << leak_bits, m=3, t=3)
    verify("rsa-coppersmith", (p - (p_high << leak_bits)) in roots,
           "Coppersmith 应恢复 p 的未知低位")


# ---------------------------------------------------------------- rsa-sign-forgery
def _forge_small_e(n, target_int):
    """教科书 RSA (e=3) 签名伪造: 找 s 使 s^3 的字节表示以 target_int 的
    字节开头且 s^3 < n. 追加 k 个零字节放大窗口 [T, (T+1)*256^k),
    k 足够大时窗口宽于相邻立方数间隔, 必有完全立方落入."""
    for k in range(200):
        lo_t = target_int << (8 * k)
        hi_t = (target_int + 1) << (8 * k)
        s = max(ctfk.iroot(lo_t, 3), 1)
        while s ** 3 < lo_t:
            s += 1
        if s ** 3 < hi_t and s ** 3 < n:
            return s
    raise RuntimeError("no forged signature found")


@register("rsa-sign-forgery")
def gen_rsa_sign_forgery(ch):
    rng = rng_for("rsa-sign-forgery")
    flag = ch["flag"]
    e = 3
    p, q, n, phi = _keypair(rng, 512, e)
    msg = b"I am the admin: grant root access"
    pub = (
        "Textbook RSA signature checker (e = 3, no padding, no hash).\n"
        "Forge a signature: write the hex signature into sig.txt next to\n"
        "this file, then run:  python verify.py\n"
        "(format: hex)\n"
        f"n = {n:x}\n"
        f"e = {e:x}\n"
    )
    write_src("rsa-sign-forgery", "pub.txt", pub)
    verifier = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 本地签名验证器 (教科书式 RSA: e = 3, 无填充, 无哈希).
# 读取同目录 sig.txt 中的十六进制签名, 立方后检查字节前缀。
MSG_PREFIX = b"I am the admin"
FLAG = {flag!r}
N = 0x{n:x}
E = 3


def main():
    try:
        s = int(open("sig.txt").read().strip(), 16)
    except Exception:
        print("REJECTED (cannot read sig.txt)")
        return
    m = pow(s, E, N)
    mb = m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b""
    if mb.startswith(MSG_PREFIX):
        print(FLAG)
    else:
        print("REJECTED")


if __name__ == "__main__":
    main()
'''
    write_src("rsa-sign-forgery", "verify.py", verifier)
    # 自检: 模拟伪造 -> 签名立方后 (不取模) 的字节串应以目标消息开头
    M = bytes_to_long(msg)
    sig = _forge_small_e(n, M)
    forged = pow(sig, e, n)
    verify("rsa-sign-forgery", sig ** 3 < n, "伪造签名必须满足 s^3 < n (pow 不取模)")
    verify("rsa-sign-forgery", long_to_bytes(forged).startswith(msg),
           "伪造签名的立方应以目标消息开头 (verify.py 应放行)")
    verify("rsa-sign-forgery", ctfk.math.gcd(e, phi) == 1, "e 与 phi 必须互素")


if __name__ == "__main__":
    run_builders(BUILDERS)
