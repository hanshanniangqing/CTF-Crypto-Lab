# -*- coding: utf-8 -*-
"""对称密码 (symmetric) + 流密码与 PRNG (stream) 分类出题脚本 (共 10 题):
symmetric: aes-key-from-secret, des-mitm, cbc-bitflip,
           ecb-byte-at-a-time, padding-oracle
stream:    rc4-keystream-reuse, xor-repeating-key, lcg-recover,
           lcg-truncated, mt19937-clone
"""
from build_common import *
import hashlib
import re

from Crypto.Cipher import AES, DES


# ======================================================================
# 公共小工具
# ======================================================================

def _des_key(i):
    """第 i 个弱 DES 密钥: 2 字节索引 + 6 个零字节 (有效熵仅 16 位)"""
    return i.to_bytes(2, "big") + b"\x00" * 6


def _des2_enc(k1, k2, block):
    """双重 DES 加密: E_k2(E_k1(block))"""
    inner = DES.new(_des_key(k1), DES.MODE_ECB).encrypt(block)
    return DES.new(_des_key(k2), DES.MODE_ECB).encrypt(inner)


def _des2_dec(k1, k2, block):
    """双重 DES 解密: D_k1(D_k2(block))"""
    inner = DES.new(_des_key(k2), DES.MODE_ECB).decrypt(block)
    return DES.new(_des_key(k1), DES.MODE_ECB).decrypt(inner)


def _des_mitm(pt, ct):
    """已知明文对 (pt, ct) 的中间相遇攻击, 返回函数等价的 (k1, k2) 或 None"""
    table = {}
    for k1 in range(65536):
        table.setdefault(DES.new(_des_key(k1), DES.MODE_ECB).encrypt(pt[:8]), k1)
    for k2 in range(65536):
        x = DES.new(_des_key(k2), DES.MODE_ECB).decrypt(ct[:8])
        if x in table:
            k1 = table[x]
            if _des2_enc(k1, k2, pt[8:16]) == ct[8:16]:
                return k1, k2
    return None


def _pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def _blocks16(data):
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def _ecb_byte_at_a_time(oracle, prefix_len):
    """逐字节恢复 ECB 预言机尾部的 flag. oracle(x) 返回 ECB(PREFIX||x||flag).
    前提: prefix_len 是 16 的倍数 (本题 = 32, flag 从块边界开始)."""
    assert prefix_len % 16 == 0
    recovered = b""
    while True:
        j = len(recovered)
        L = ((15 - j) % 16) + 16          # L + j ≡ 15 (mod 16), 且 L >= 16
        k = (prefix_len + L + j) // 16     # 目标块: 末字节恰为 flag[j]
        real = _blocks16(oracle(b"A" * L))[k]
        group = L + j + 1                  # ≡ 0 (mod 16), 字典查询各组自动对齐
        payload = b"".join(b"A" * L + recovered + bytes([c]) for c in range(256))
        dblocks = _blocks16(oracle(payload))
        hit = None
        for c in range(256):
            if dblocks[k + c * (group // 16)] == real:
                hit = c
                break
        if hit is None:
            break
        recovered += bytes([hit])
        if hit == ord("}"):
            break
    return recovered


def _poa_recover_block(query, c_target, c_prev):
    """恢复中间值 D(c_target). query(prev16) -> bool: 以 prev'||c_target 询问
    padding 预言机 (c_prev 作 IV). 从最后一个字节向前逐字节确定."""
    mid = [0] * 16

    def probe(i, g, tweak=None):
        prev = bytearray(c_prev)
        for kk in range(i + 1, 16):
            prev[kk] = mid[kk] ^ (16 - i)
        if tweak is not None:
            prev[14] ^= tweak
        prev[i] = g
        return query(bytes(prev) + c_target)

    for i in range(15, -1, -1):
        cands = [g for g in range(256) if probe(i, g)]
        if len(cands) > 1:
            # 只有最后一字节可能歧义 (更长的合法填充恰好也存在):
            # 扰动倒数第二字节重测, 真正的 0x01 填充依然有效
            good = None
            for t in range(1, 256):
                good = [g for g in cands if probe(i, g, tweak=t)]
                if len(good) == 1:
                    break
            cands = good
        if len(cands) != 1:
            raise RuntimeError("padding oracle attack failed at byte %d" % i)
        mid[i] = cands[0] ^ (16 - i)
    return bytes(mid)


def _poa_recover(query, iv, blocks):
    """对 CBC 密文 (iv || blocks) 做 padding oracle 攻击, 返回含填充的明文"""
    plain = b""
    prev = iv
    for cb in blocks:
        dmid = _poa_recover_block(query, cb, prev)
        plain += ctfk.xor_bytes(dmid, prev)
        prev = cb
    return plain


# ======================================================================
# 对称密码 (symmetric)
# ======================================================================
_USERNAMES = ["alice", "bob", "root", "svc-backup", "deploy-bot", "test", "admin2"]


@register("aes-key-from-secret")
def gen_aes_key_from_secret(ch):
    flag = ch["flag"].encode()
    ini = (
        "# leaked from the deploy pipeline, 2026-10-25\n"
        "# The backup service derives its AES key from the operator account:\n"
        "#     aes_key = md5('key:' + username).digest()[:16]\n"
        "[accounts]\n"
        "usernames = " + ", ".join(_USERNAMES) + "\n"
    )
    write_src("aes-key-from-secret", "leaked-config.ini", ini)
    key = hashlib.md5(b"key:svc-backup").digest()[:16]
    ct = AES.new(key, AES.MODE_ECB).encrypt(ctfk.pkcs7_pad(flag))
    write_src("aes-key-from-secret", "flag.enc", ct.hex() + "\n")

    # 自检
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    verify("aes-key-from-secret", ctfk.pkcs7_unpad(pt) == flag,
           "用 svc-backup 派生密钥解密应恢复 flag")
    names = []
    for line in ini.splitlines():
        if line.lower().startswith("usernames"):
            names = [u.strip() for u in line.split("=", 1)[1].split(",") if u.strip()]
    verify("aes-key-from-secret", names == _USERNAMES, "ini 用户名列表应可完整解析")
    hits = [u for u in names
            if AES.new(hashlib.md5(b"key:" + u.encode()).digest()[:16],
                       AES.MODE_ECB).decrypt(ct).startswith(b"flag{")]
    verify("aes-key-from-secret", hits == ["svc-backup"],
           "候选用户名逐个解密应恰好命中 svc-backup")


@register("des-mitm")
def gen_des_mitm(ch):
    rng = rng_for("des-mitm")
    k1 = rng.randrange(65536)
    k2 = rng.randrange(65536)
    # 注: b"ATTACKATDAWN" 只有 12 字节, 补 4 个 NOL 凑成 2 个完整 DES 块,
    # 这样中间相遇可以用第一块建表、第二块验证。
    pt = b"ATTACKATDAWN" + b"\x00" * 4
    known_ct = _des2_enc(k1, k2, pt[:8]) + _des2_enc(k1, k2, pt[8:16])
    flagpad = ch["flag"].encode()
    flagpad += b"\x00" * ((-len(flagpad)) % 8)
    target = b"".join(_des2_enc(k1, k2, flagpad[i:i + 8])
                      for i in range(0, len(flagpad), 8))
    write_src("des-mitm", "known_pair.txt", (
        "# double-DES sample: ct = E_k2(E_k1(pt)), DES-ECB, 8-byte blocks\n"
        "# pt is the ASCII text 'ATTACKATDAWN' zero-padded to 16 bytes\n"
        "# weak key space: key(i) = i.to_bytes(2, 'big') + b'\\x00' * 6,\n"
        "#                 i in [0, 65536)  (only 16 bits of entropy per key)\n"
        "pt = %s\n"
        "ct = %s\n" % (pt.hex(), known_ct.hex())))
    write_src("des-mitm", "target.txt", (
        "# double-DES ciphertext of the flag\n"
        "# (flag padded with NUL bytes to a multiple of 8, encrypted blockwise)\n"
        "target = %s\n" % target.hex()))

    # 自检
    verify("des-mitm", len(flagpad) == 32 and len(target) == 32,
           "flag pad 与 target 均应为 4 个 DES 块")
    verify("des-mitm", _des2_dec(k1, k2, known_ct[:8]) == pt[:8]
           and _des2_dec(k1, k2, known_ct[8:]) == pt[8:],
           "已知明文对应可由双层密钥解出")
    got = _des_mitm(pt, known_ct)
    verify("des-mitm", got is not None, "中间相遇攻击应找到候选密钥对")
    if got is not None:
        k1r, k2r = got
        dec = b"".join(_des2_dec(k1r, k2r, target[i:i + 8])
                       for i in range(0, len(target), 8))
        verify("des-mitm", dec == flagpad, "MITM 密钥解密 target 应恢复 flag pad")


_CBC_SERVER = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cbc-bitflip —— 令牌授权服务 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  TOKEN <hex iv><hex ct>
#   客户端每次发送:        ATTEMPT <hex iv'>
#   服务端用【原密文 ct】+ 新 IV 解密, 检查明文是否提权为 admin:
#                          GRANTED <flag>   (明文中出现 ROLE=admin 或 USER=admin)
#                          DENIED           (否则) / ERR (请求格式错误)
#   发送 QUIT 或断开连接结束会话。
#
# 令牌明文固定为: USER=guest;ROLE=user;EXP=20301231
# (33 字节, pkcs7 填充到 48 字节 = 3 个 AES 块)
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = {flag!r}
KEY = os.urandom(16)
TOKEN_PLAIN = b"USER=guest;ROLE=user;EXP=20301231"


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def handle(conn):
    iv = os.urandom(16)
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pkcs7_pad(TOKEN_PLAIN))
    conn.sendall(("TOKEN %s%s\n" % (iv.hex(), ct.hex())).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "ATTEMPT" and len(parts) > 1:
                try:
                    iv2 = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(iv2) != 16:
                    conn.sendall(b"ERR\n")
                    continue
                pt = AES.new(KEY, AES.MODE_CBC, iv2).decrypt(ct)
                if b"ROLE=admin" in pt or b"USER=admin" in pt:
                    conn.sendall(("GRANTED %s\n" % FLAG).encode())
                else:
                    conn.sendall(b"DENIED\n")
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


@register("cbc-bitflip")
def gen_cbc_bitflip(ch):
    write_src("cbc-bitflip", "server.py", _CBC_SERVER.format(flag=ch["flag"]))
    # 自检: 用一次性随机 key/iv 本地演算 IV 比特翻转 (不走网络)
    rng = rng_for("cbc-bitflip")
    key = rng.randrange(2 ** 128).to_bytes(16, "big")
    iv = rng.randrange(2 ** 128).to_bytes(16, "big")
    token = b"USER=guest;ROLE=user;EXP=20301231"
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(ctfk.pkcs7_pad(token))
    p1_known = b"USER=guest;ROLE="
    p1_target = b"USER=admin;ROLE="
    iv2 = ctfk.xor_bytes(iv, ctfk.xor_bytes(p1_known, p1_target))
    pt2 = AES.new(key, AES.MODE_CBC, iv2).decrypt(ct)
    verify("cbc-bitflip", len(ctfk.pkcs7_pad(token)) == 48, "令牌应 pkcs7 填充到 3 个块")
    verify("cbc-bitflip", pt2[:16] == p1_target, "翻转 IV 后第一块明文应等于目标串")
    verify("cbc-bitflip", b"ROLE=admin" in pt2 or b"USER=admin" in pt2,
           "翻转后应满足 server.py 的 GRANTED 条件")


_ECB_SERVER = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ecb-byte-at-a-time —— ECB 加密预言机 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  ECB-ORACLE ready. prefix length = 32
#   客户端每次发送:        ENC <hex data>
#   服务端回答:            AES-128-ECB( PREFIX || data || FLAG ) 的 hex,
#                          加密前对整体做 pkcs7 填充。
#                          PREFIX 是启动时生成的 32 字节随机前缀, 进程存续
#                          期间固定不变 (长度恰好为 2 个块)。
#   发送 QUIT 或断开连接结束会话。
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = {flag!r}
KEY = os.urandom(16)
PREFIX = os.urandom(32)   # 进程存续期间固定, 长度 32


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def handle(conn):
    conn.sendall(b"ECB-ORACLE ready. prefix length = 32\n")
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "ENC" and len(parts) > 1:
                try:
                    x = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(x) > 1000000:
                    conn.sendall(b"ERR\n")
                    continue
                buf = pkcs7_pad(PREFIX + x + FLAG.encode())
                conn.sendall(AES.new(KEY, AES.MODE_ECB).encrypt(buf).hex().encode() + b"\n")
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


@register("ecb-byte-at-a-time")
def gen_ecb_byte_at_a_time(ch):
    write_src("ecb-byte-at-a-time", "server.py", _ECB_SERVER.format(flag=ch["flag"]))
    # 自检: 本地 (不走网络) 用一次性随机 key/前缀完整模拟逐字节攻击
    rng = rng_for("ecb-byte-at-a-time")
    key = rng.randrange(2 ** 128).to_bytes(16, "big")
    prefix = rng.randrange(2 ** 256).to_bytes(32, "big")
    flag = ch["flag"].encode()

    def oracle(x):
        return AES.new(key, AES.MODE_ECB).encrypt(_pkcs7_pad(prefix + x + flag))

    rec = _ecb_byte_at_a_time(oracle, 32)
    verify("ecb-byte-at-a-time", len(flag) == 30, "flag 应为 30 字节")
    verify("ecb-byte-at-a-time", rec == flag, "本地模拟逐字节攻击应完整恢复 flag")


_PO_SERVER = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# padding-oracle —— CBC 解密填充预言机 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  CT <hex iv><hex c1><hex c2><hex c3>
#   客户端每次发送:        DEC <hex data>
#                          data = iv' || 若干个 16 字节密文块
#   服务端以 iv' 为 IV 做 CBC 解密, 检查明文尾部的 pkcs7 填充:
#                          OK    (填充合法)
#                          ERR   (填充非法 / 请求格式错误)
#   发送 QUIT 或断开连接结束会话。
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = {flag!r}
KEY = os.urandom(16)
IV = os.urandom(16)


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_valid(data, block=16):
    if not data or len(data) % block:
        return False
    n = data[-1]
    return 1 <= n <= block and data[-n:] == bytes([n]) * n


PT = pkcs7_pad(FLAG.encode())
CT = AES.new(KEY, AES.MODE_CBC, IV).encrypt(PT)


def handle(conn):
    conn.sendall(("CT %s%s\n" % (IV.hex(), CT.hex())).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "DEC" and len(parts) > 1:
                try:
                    data = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(data) < 32 or (len(data) - 16) % 16:
                    conn.sendall(b"ERR\n")
                    continue
                pt = AES.new(KEY, AES.MODE_CBC, data[:16]).decrypt(data[16:])
                conn.sendall(b"OK\n" if pkcs7_valid(pt) else b"ERR\n")
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


@register("padding-oracle")
def gen_padding_oracle(ch):
    write_src("padding-oracle", "server.py", _PO_SERVER.format(flag=ch["flag"]))
    # 自检: 本地 (不走网络) 用一次性随机 key/iv 完整模拟 POA
    rng = rng_for("padding-oracle")
    key = rng.randrange(2 ** 128).to_bytes(16, "big")
    iv = rng.randrange(2 ** 128).to_bytes(16, "big")
    flag = ch["flag"].encode()
    pt = ctfk.pkcs7_pad(flag)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
    blocks = _blocks16(ct)

    def query(data):
        p = AES.new(key, AES.MODE_CBC, data[:16]).decrypt(data[16:])
        return ctfk.pkcs7_valid(p)

    verify("padding-oracle", len(flag) == 36 and len(blocks) == 3,
           "flag 36 字节应填充为 3 个密文块 (IV||C1||C2||C3)")
    rec = _poa_recover(query, iv, blocks)
    verify("padding-oracle", rec == pt, "本地 POA 模拟应恢复含填充的明文")
    verify("padding-oracle", ctfk.pkcs7_unpad(rec) == flag, "去填充后应为 flag")


# ======================================================================
# 流密码与 PRNG (stream)
# ======================================================================

@register("rc4-keystream-reuse")
def gen_rc4_keystream_reuse(ch):
    rng = rng_for("rc4-keystream-reuse")
    key = bytes(rng.randrange(256) for _ in range(16))
    msg1 = b"SESSION LOG v2.3|user=guest|ts=2026-10-25T09:00:00|action=login|"
    msg2 = b"secret note: flag{rc4_never_reuse_keystream} keep it safe"
    ct1 = ctfk.rc4(key, msg1)
    ct2 = ctfk.rc4(key, msg2)
    write_src("rc4-keystream-reuse", "known_plain.txt", msg1)  # 原样字节
    write_src("rc4-keystream-reuse", "two_ciphertexts.txt", (
        "# two messages encrypted with the SAME RC4 key (hex)\n"
        "ct1 = %s\n"
        "ct2 = %s\n" % (ct1.hex(), ct2.hex())))

    # 自检
    verify("rc4-keystream-reuse", len(msg2) <= len(msg1),
           "msg2 必须不长于 msg1 (密钥流完全覆盖)")
    ks = ctfk.xor_bytes(ct1, msg1)
    pt2 = ctfk.xor_bytes(ct2, ks[: len(ct2)])
    verify("rc4-keystream-reuse", pt2 == msg2, "密钥流复用解密应恢复 msg2")
    verify("rc4-keystream-reuse", ch["flag"].encode() in pt2, "msg2 应包含 flag")


def _xor_keylen_order(ct):
    """汉明距离估密钥长度: 返回按归一化距离升序的候选长度表"""
    scores = {}
    for k in range(2, 41):
        n = min(8, len(ct) // k - 1)
        if n < 2:
            continue
        tot = sum(ctfk.hamming_bits(ct[b * k:(b + 1) * k],
                                    ct[(b + 1) * k:(b + 2) * k]) / k
                  for b in range(n))
        scores[k] = tot / n
    return sorted(scores, key=lambda k: scores[k])


_PUNCT = ".,'\";:!?-()"


def _col_score(text):
    """英文可见字符加权评分 (越大越像英文). 区分大小写:
    chi2_english 会 lower() 导致 x 与 x^0x40 平分, 且对几乎没有字母的
    列给出虚假低分, 因此这里改用带权打分."""
    s = 0.0
    for ch in text:
        low = ch.lower()
        if ch == " ":
            s += 1.8
        elif "a" <= low <= "z":
            s += (ctfk.ENGLISH_FREQ[low] / 8.2) * (1.0 if ch == low else 0.4)
        elif ch in _PUNCT:
            s += 0.3
        elif 32 <= ord(ch) < 127:
            s -= 1.0
        else:
            s -= 8.0
    return s


def _xor_solve_flag(ct):
    """分列单字节 XOR + 可见字符加权评分, 返回 flag 字符串或 None"""
    for k in _xor_keylen_order(ct):
        key = bytes(max(range(256),
                        key=lambda g, col=ct[j::k]:
                        _col_score(ctfk.xor_bytes(col, bytes([g])).decode("latin-1")))
                    for j in range(k))
        text = ctfk.xor_bytes(ct, key).decode("latin-1")
        m = re.search(r"flag\{[^}\s]*\}", text)
        if m:
            return m.group(0)
    return None


@register("xor-repeating-key")
def gen_xor_repeating_key(ch):
    rng = rng_for("xor-repeating-key")
    corpus = (LAB / "lib" / "data" / "corpus_en.txt").read_text(
        encoding="utf-8", errors="ignore")
    sent = ("Note that the access code flag{repeating_key_repeating_pain} "
            "was rotated yesterday.")
    start = rng.randrange(0, len(corpus) - 5000)
    raw = "".join(c if 32 <= ord(c) < 127 else " "
                  for c in corpus[start:start + 1200])
    pos = rng.randrange(200, 900)
    pt = raw[:pos] + sent + raw[pos:]
    key = bytes(rng.randrange(256) for _ in range(7))
    ct = ctfk.xor_bytes(pt.encode("ascii"), key)
    hexed = ct.hex()
    lines = "\n".join(hexed[i:i + 64] for i in range(0, len(hexed), 64))
    write_src("xor-repeating-key", "ciphertext.txt",
              "# repeating-key XOR, key length between 2 and 40, hex:\n"
              + lines + "\n")

    # 自检
    verify("xor-repeating-key", len(pt) >= 900, "明文应至少 900 字符")
    verify("xor-repeating-key", sent in pt, "flag 句子必须完整插入明文")
    verify("xor-repeating-key",
           ctfk.xor_bytes(ct, key).decode("ascii") == pt, "密钥异或应自洽")
    found = _xor_solve_flag(ct)
    verify("xor-repeating-key", found == ch["flag"],
           "统计解法 (hamming+chi2) 应恢复 flag, got %r" % (found,))


@register("lcg-recover")
def gen_lcg_recover(ch):
    # 注: 规格原设想的「flag 4 段 = 接下来 4 个输出」在数学上不成立——
    # 任意 4 段明文无法满足 x_{i+1} = a*x_i + c 的 3 个约束 (仅 2 个自由度)。
    # 故改为: 接下来 4 个输出拼成 32 字节掩码, 与 flag pad 异或后放入
    # mask.txt。参数恢复 + 预测输出的考点完全保留。
    rng = rng_for("lcg-recover")
    m = 2 ** 64 - 59
    flagpad = ch["flag"].encode()
    flagpad += b"\x00" * ((-len(flagpad)) % 8)
    n_out, n_fut = 8, len(flagpad) // 8
    while True:  # 确定性重摇, 直到参数可由 solve_lcg_params 精确恢复
        a = rng.randrange(1, m)
        c = rng.randrange(m)
        if ctfk.math.gcd(a, m) != 1:
            continue
        seed = rng.randrange(m)
        gen = ctfk.LCG(a, c, m, seed)
        seq = [gen.next() for _ in range(n_out + n_fut)]
        outs, fut = seq[:n_out], seq[n_out:]
        if ctfk.solve_lcg_params(outs) != (m, a, c):
            continue
        break
    mask_stream = b"".join(v.to_bytes(8, "big") for v in fut)
    mask_enc = ctfk.xor_bytes(flagpad, mask_stream)
    txt = ["LCG output capture",
           "generator: x_next = (a * x + c) mod m   (full 64-bit values)",
           "%d consecutive outputs (decimal):" % n_out,
           ""]
    txt += ["o%d = %d" % (i + 1, v) for i, v in enumerate(outs)]
    txt += ["",
            "note: the NEXT %d outputs, each written as an 8-byte big-endian" % n_fut,
            "integer and concatenated, form a 32-byte pad. XOR that pad with",
            "mask.txt (hex, in this directory) to get the flag (strip NULs).",
            ""]
    write_src("lcg-recover", "output.txt", "\n".join(txt))
    write_src("lcg-recover", "mask.txt", mask_enc.hex() + "\n")

    # 自检
    got = ctfk.solve_lcg_params(outs)
    verify("lcg-recover", got == (m, a, c), "solve_lcg_params 应恢复 (m, a, c)")
    _, aa, cc = got
    lcg2 = ctfk.LCG(aa, cc, got[0], outs[-1])
    stream = b"".join(lcg2.next().to_bytes(8, "big") for _ in range(n_fut))
    pad = ctfk.xor_bytes(mask_enc, stream)
    verify("lcg-recover", pad == flagpad, "预测输出 + 掩码异或应还原 flag pad")
    verify("lcg-recover", pad.rstrip(b"\x00").decode() == ch["flag"],
           "去尾部 NUL 后应为 flag")


_LCG_TRUNC_SRC = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rng_service.py —— 某摇号服务的截断输出实现
#
# 生成器是线性同余:  x_{{i+1}} = (A * x_i + C) mod M
# 运维只把每个状态的高 32 位写进日志 (见 outputs.txt, 每行一个 hex 值,
# 低 32 位被丢弃)。
#
# 提示: 接下来的 {n_chunks} 个【完整】输出, 每个按 8 字节大端编码后依次
# 连接成 32 字节 pad, 与 mask.txt (hex) 异或即是 flag (去掉尾部 NUL)。

M = {m}   # 2**64 - 59 (素数)
A = {a}
C = {c}


class TruncatedLCG:
    def __init__(self, seed):
        self.s = seed % M

    def next(self):
        self.s = (A * self.s + C) % M
        return self.s

    def next_logged(self):
        return format(self.next() >> 32, "08x")
'''


@register("lcg-truncated")
def gen_lcg_truncated(ch):
    # 与 lcg-recover 相同的原因: flag 4 段无法直接作为连续输出, 改用
    # 「后续输出拼接成掩码流 XOR flag pad」的嵌入方式 (见 gen_lcg_recover)。
    rng = rng_for("lcg-truncated")
    m = 2 ** 64 - 59
    flagpad = ch["flag"].encode()
    flagpad += b"\x00" * ((-len(flagpad)) % 8)
    n_out, n_fut = 16, len(flagpad) // 8
    while True:  # 确定性重摇, 直到格攻击能完整恢复状态
        a = rng.randrange(1, m)
        c = rng.randrange(m)
        if ctfk.math.gcd(a, m) != 1:
            continue
        seed = rng.randrange(m)
        gen = ctfk.LCG(a, c, m, seed)
        seq = [gen.next() for _ in range(n_out + n_fut)]
        outs, fut = seq[:n_out], seq[n_out:]
        highs = [o >> 32 for o in outs]
        try:
            st = ctfk.solve_lcg_truncated(m, a, c, highs, 32)
        except Exception:
            st = None
        if st is None or st[-1] != outs[-1]:
            continue
        break
    mask_stream = b"".join(v.to_bytes(8, "big") for v in fut)
    mask_enc = ctfk.xor_bytes(flagpad, mask_stream)
    write_src("lcg-truncated", "source.py",
              _LCG_TRUNC_SRC.format(m=m, a=a, c=c, n_chunks=n_fut))
    write_src("lcg-truncated", "outputs.txt",
              "# high 32 bits (hex) of %d consecutive outputs\n" % n_out
              + "\n".join(format(h, "08x") for h in highs) + "\n")
    write_src("lcg-truncated", "mask.txt", mask_enc.hex() + "\n")

    # 自检
    verify("lcg-truncated", st[-1] == outs[-1], "格恢复的最后状态应等于 o16")
    lcg2 = ctfk.LCG(a, c, m, st[-1])
    stream = b"".join(lcg2.next().to_bytes(8, "big") for _ in range(n_fut))
    pad = ctfk.xor_bytes(mask_enc, stream)
    verify("lcg-truncated", pad == flagpad, "恢复状态续推 + 掩码异或应还原 flag pad")
    verify("lcg-truncated", pad.rstrip(b"\x00").decode() == ch["flag"],
           "去尾部 NUL 后应为 flag")


@register("mt19937-clone")
def gen_mt19937_clone(ch):
    rng = rng_for("mt19937-clone")
    mt = ctfk.MT19937(rng.randrange(2 ** 32))
    outs = [mt.next32() for _ in range(624)]
    flag = ch["flag"].encode()
    ks = mt.next_bytes(len(flag))
    ct = ctfk.xor_bytes(flag, ks)
    write_src("mt19937-clone", "outputs.txt",
              "\n".join(str(o) for o in outs) + "\n")
    write_src("mt19937-clone", "flag.enc", ct.hex() + "\n")

    # 自检
    verify("mt19937-clone", len(outs) == 624, "需要恰好 624 个连续输出")
    clone = ctfk.clone_mt(outs)
    pt = ctfk.xor_bytes(ct, clone.next_bytes(len(ct)))
    verify("mt19937-clone", pt == flag, "克隆生成器的密钥流应解出 flag")
    verify("mt19937-clone", clone.next_bytes(4) == mt.next_bytes(4),
           "克隆与原生成器此后的输出应完全一致")


if __name__ == "__main__":
    run_builders(BUILDERS)
