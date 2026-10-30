# -*- coding: utf-8 -*-
"""
toolkit_web.py — 密码工具箱 (独立 Web 界面, 纯标准库)

  python ctf.py toolkit [--port 8788]

左侧工具分组, 右侧表单化操作; 所有计算在本地服务端完成 (lib/ctfk.py),
结果带步骤说明, 支持一键复制。适合做题时随手算、验证思路。
"""
import base64
import binascii
import hashlib
import json
import math
import random
import re
import sys
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB / "lib"))
sys.path.insert(0, str(LAB / "tools"))

import ctfk  # noqa: E402
from webbase import BASE_CSS, JS_HELPERS  # noqa: E402

# ======================================================================
# 输入/输出辅助
# ======================================================================

def pint(s, default=None):
    """解析大整数: 支持 0x 前缀 / 含 a-f 视为十六进制 / 下划线与空格分隔"""
    if s is None or str(s).strip() == "":
        if default is not None:
            return default
        raise ValueError("缺少整数输入")
    t = str(s).strip().replace("_", "").replace(" ", "")
    neg = t.startswith("-")
    if neg:
        t = t[1:]
    if t.lower().startswith("0x"):
        v = int(t, 16)
    elif re.fullmatch(r"[0-9]+", t):
        v = int(t, 10)
    elif re.fullmatch(r"[0-9a-fA-F]+", t):
        v = int(t, 16)
    else:
        raise ValueError(f"无法解析整数: {s!r}")
    return -v if neg else v


def pbytes(s, is_hex=False):
    s = "" if s is None else str(s)
    if is_hex:
        return bytes.fromhex(re.sub(r"\s|0x", "", s))
    return s.encode("utf-8", "surrogateescape")


def pstr(b):
    """bytes -> 展示文本 (可打印则原文, 否则 hex)"""
    if isinstance(b, str):
        return b
    try:
        t = b.decode("utf-8")
        if all(c == "\n" or c == "\t" or 32 <= ord(c) < 0x7f or ord(c) > 0x2000 for c in t):
            return t
    except UnicodeDecodeError:
        pass
    return b.hex()


def big(v):
    """大整数的展示 (十进制 + 十六进制)"""
    if not isinstance(v, int):
        return str(v)
    h = format(v, "x")
    if len(h) > 96:
        h = h[:48] + " … " + h[-40:]
    return f"{v}\n(hex) {h}" if len(str(v)) > 40 else str(v)


def _split_ints(s):
    return [pint(x) for x in re.split(r"[\s,;]+", (s or "").strip()) if x]


# ---- 四元组英文模型 (替代/维吉尼亚/XOR 的标准评分器) ----
_QUAD = None
_QUAD_FLOOR = 0.0


def _quad_load():
    global _QUAD, _QUAD_FLOOR
    if _QUAD is not None:
        return _QUAD
    try:
        text = (LAB / "lib" / "data" / "corpus_en.txt").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = "the quick brown fox jumps over the lazy dog " * 400
    text = re.sub(r"[^a-z]+", "", text.lower())
    counts = {}
    for i in range(len(text) - 3):
        g = text[i:i + 4]
        counts[g] = counts.get(g, 0) + 1
    total = max(1, sum(counts.values()))
    _QUAD = {g: math.log(c / total) for g, c in counts.items()}
    _QUAD_FLOOR = math.log(0.01 / total)
    return _QUAD


def qscore(s):
    """英文四元组平均对数概率 (越高越像英文)"""
    q = _quad_load()
    s = re.sub(r"[^a-z]", "", s.lower())
    if len(s) < 4:
        return -1e9
    return sum(q.get(s[i:i + 4], _QUAD_FLOOR) for i in range(len(s) - 3)) / (len(s) - 3)


def eng_score(s):
    """自适应英文评分 (越大越好): 短文本用卡方 (字母频率更稳), 长文本用四元组"""
    n = sum(1 for c in s if c.isalpha())
    if n < 50:
        return -ctfk.chi2_english(s)
    return qscore(s) * 10.0


def rank_blend(texts):
    """四元组 + 卡方 双重排名融合 (返回索引顺序, 最像英文在前).
    短文本时两个指标各有偏差, 排名求和比单一指标稳健。"""
    n = len(texts)
    by_q = sorted(range(n), key=lambda i: -qscore(texts[i]))
    by_c = sorted(range(n), key=lambda i: ctfk.chi2_english(texts[i]))
    rq = {i: r for r, i in enumerate(by_q)}
    rc = {i: r for r, i in enumerate(by_c)}
    return sorted(range(n), key=lambda i: rq[i] + rc[i])


def xor_score(s):
    """XOR 明文评分: 英文四元组 + 可打印比例奖励"""
    printable = sum(1 for c in s if 32 <= ord(c) < 127) / max(1, len(s))
    return qscore(s) + 3.0 * printable


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def ok(result, extras=None, steps=None, t0=None):
    return {"ok": True, "result": result, "extras": extras or [],
            "steps": steps or [], "elapsed": round(time.time() - t0, 3) if t0 else 0}


def fail(msg):
    return {"ok": False, "error": str(msg)}


# ======================================================================
# 编码工具
# ======================================================================

def t_auto(f):
    data = pbytes(f.get("data"), f.get("is_hex") == "1")
    out, layers = ctfk.try_decode_layers(data)
    return ok(pstr(out), [("剥壳层级", " → ".join(layers) if layers else "(无)"),
                          ("长度", f"{len(out)} 字节")])


def t_hex(f):
    mode = f.get("mode", "dec")
    if mode == "enc":
        b = pbytes(f.get("data"))
        return ok(b.hex(), [("大写", b.hex().upper())])
    b = pbytes(f.get("data"), is_hex=True)
    return ok(pstr(b), [("字节数", len(b))])


def t_base(f):
    scheme, mode = f.get("scheme", "64"), f.get("mode", "dec")
    raw = "" if f.get("data") is None else str(f.get("data")).strip()
    if mode == "enc":
        b = pbytes(raw)
        if scheme == "64":
            return ok(base64.b64encode(b).decode())
        if scheme == "32":
            return ok(base64.b32encode(b).decode())
        if scheme == "85":
            return ok(base64.a85encode(b).decode())
        return ok(base64.urlsafe_b64encode(b).decode())
    if scheme == "64":
        b = base64.b64decode(raw + "=" * (-len(raw) % 4))
    elif scheme == "64url":
        b = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    elif scheme == "32":
        b = base64.b32decode(raw + "=" * (-len(raw) % 8))
    else:
        b = base64.a85decode(raw)
    return ok(pstr(b), [("字节数", len(b))])


def t_url(f):
    from urllib.parse import unquote
    s = str(f.get("data") or "")
    d = unquote(s)
    return ok(d, [("变化", "无" if d == s else "已解码")])


def t_caesar(f):
    mode = f.get("mode", "dec")
    s = str(f.get("data") or "")
    if mode == "brute":
        rows = [(k, ctfk.caesar_shift(s, -k)) for k in range(26)]
        order = rank_blend([t for _, t in rows])
        lines = [f"[shift={rows[i][0]:2d}] {rows[i][1][:160]}" for i in order[:5]]
        return ok("\n".join(lines), [("评分方式", "卡方 (越小越像英文)")])
    k = pint(f.get("shift"), 3) % 26
    res = ctfk.caesar_shift(s, k if mode == "enc" else -k)
    return ok(res)


def t_morse(f):
    table = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
             "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
             "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
             "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
             "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
             "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
             "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
             "/": "-..-.", "'": ".----.", "!": "-.-.--", "@": ".--.-.", "-": "-....-"}
    inv = {v: k for k, v in table.items()}
    s = str(f.get("data") or "").strip()
    if f.get("mode", "dec") == "enc":
        return ok(" / ".join(" ".join(table.get(c, "") for c in w.upper()) for w in s.split()))
    words = re.split(r"\s*/\s*|\s{3,}", s)
    out = []
    for w in words:
        out.append("".join(inv.get(tok, "?") for tok in w.split()))
    return ok(" ".join(out))


# ======================================================================
# 古典工具
# ======================================================================

def t_vigenere(f):
    mode = f.get("mode", "dec")
    s = str(f.get("data") or "")
    if mode == "crack":
        letters = [c.lower() for c in s if c.isalpha()]
        n = len(letters)
        if n < 12:
            raise ValueError("密文太短 (建议 ≥ 40 字母)")
        # 1) 重合指数估计候选密钥长度 (取 top 3, 因为倍数也会偏高)
        def decrypt_with(key):
            return "".join(chr((ord(ch) - 97 - key[i % len(key)]) % 26 + 97)
                           for i, ch in enumerate(letters))

        # 先按 IC 粗排长度, 再用四元组评分 + 逐位爬山精确求解
        ic_len = []
        for L in range(2, 17):
            if n < L * 3:
                break
            ics = []
            for i in range(L):
                col = letters[i::L]
                cnt = {}
                for c in col:
                    cnt[c] = cnt.get(c, 0) + 1
                m = len(col)
                ics.append(sum(v * (v - 1) for v in cnt.values()) / (m * (m - 1)) if m > 1 else 0)
            ic_len.append((sum(ics) / len(ics), L))
        ic_len.sort(reverse=True)
        lens = [L for _, L in ic_len] or [2]
        best = None
        for L in lens:
            key = []
            for i in range(L):
                col = "".join(letters[i::L])
                key.append(min(range(26), key=lambda k: ctfk.chi2_english(ctfk.caesar_shift(col, -k))))
            cur = qscore(decrypt_with(key))
            for _ in range(4):
                improved = False
                for pos in range(L):
                    bk, bs = key[pos], cur
                    for k in range(26):
                        if k == key[pos]:
                            continue
                        key[pos] = k
                        sc = qscore(decrypt_with(key))
                        if sc > bs:
                            bs, bk = sc, k
                    key[pos] = bk
                    if bs > cur:
                        cur, improved = bs, True
                if not improved:
                    break
            if best is None or cur > best[0] + 1e-9:
                best = (cur, list(key), decrypt_with(key))
        score, key, plain = best
        # 密钥若是周期的, 约简到最小周期 (解密结果等价, 展示更干净)
        for per in range(1, len(key)):
            if all(key[i] == key[i % per] for i in range(len(key))):
                k2 = key[:per]
                s2 = qscore(decrypt_with(k2))
                if s2 >= score - 1e-9:
                    score, key, plain = s2, k2, decrypt_with(k2)
                break
        return ok(plain, [("密钥长度", len(key)),
                          ("推导密钥", "".join(chr(97 + k) for k in key)),
                          ("英文四元组评分", round(score, 4))])
    key = str(f.get("key") or "")
    if not key:
        raise ValueError("需要密钥")
    return ok(ctfk.vigenere(s, key, decrypt=(mode == "dec")), [("密钥", key)])
    key = str(f.get("key") or "")
    if not key:
        raise ValueError("需要密钥")
    return ok(ctfk.vigenere(s, key, decrypt=(mode == "dec")), [("密钥", key)])


def t_affine(f):
    s = str(f.get("data") or "")
    rows = []
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        for b in range(26):
            t = ctfk.affine_decrypt(s, a, b)
            rows.append((-eng_score(t), a, b, t))
    rows.sort()
    best = rows[:5]
    lines = [f"[a={a:2d} b={b:2d} score={sc:8.3f}] {t[:150]}" for sc, a, b, t in best]
    return ok("\n".join(lines), [("尝试密钥数", len(rows))])


def t_playfair(f):
    key = str(f.get("key") or "")
    if not key:
        raise ValueError("需要密钥")
    pf = ctfk.Playfair(key)
    s = str(f.get("data") or "")
    if f.get("mode", "dec") == "enc":
        return ok(pf.encrypt(s), [("密钥方阵", " / ".join("".join(r) for r in pf.sq))])
    return ok(pf.decrypt(s))


def t_hill(f):
    s = str(f.get("data") or "")
    mode = f.get("mode", "dec")
    if mode == "kpa":
        pt = re.sub(r"[^a-z]", "", str(f.get("pt") or "").lower())
        ct = re.sub(r"[^a-z]", "", str(f.get("ct") or "").lower())
        k = 2 if len(pt) < 12 else 3
        pb = [[ord(c) - 97 for c in pt[i * k:(i + 1) * k]] for i in range(len(pt) // k)]
        cb = [[ord(c) - 97 for c in ct[i * k:(i + 1) * k]] for i in range(len(ct) // k)]
        for start in range(max(0, len(pb) - k)):
            K = ctfk.hill_key_from_knownpt(pb[start:start + k], cb[start:start + k])
            if K:
                return ok("\n".join(" ".join(f"{v:2d}" for v in row) for row in K),
                          [("密钥尺寸", f"{k}×{k}"), ("使用块", f"第 {start + 1} 起")])
        return fail("已知明密文不足以恢复密钥 (矩阵不可逆)")
    K = []
    nums = [pint(x) for x in re.split(r"[\s,;]+", str(f.get("key") or "")) if x != ""]
    n = int(round(math.sqrt(len(nums))))
    if n * n != len(nums):
        raise ValueError("密钥矩阵需为 n×n 个整数")
    for i in range(n):
        K.append([v % 26 for v in nums[i * n:(i + 1) * n]])
    try:
        Kinv = ctfk.mat_inv_mod(K, 26)
    except ValueError:
        raise ValueError("密钥矩阵不可逆 (det 与 26 不互素)")
    letters = re.sub(r"[^a-z]", "", s.lower())
    out = []
    for i in range(0, len(letters) - n + 1, n):
        blk = [[ord(c) - 97 for c in letters[i:i + n]]]
        out.append("".join(chr(v + 97) for v in ctfk.mat_mul_mod(blk, Kinv, 26)[0]))
    return ok("".join(out), [("密钥逆矩阵", str(Kinv))])


def t_railfence(f):
    s = str(f.get("data") or "")
    r = pint(f.get("rails"), 3)
    if r < 2:
        raise ValueError("栏数需 ≥ 2")
    if f.get("mode", "dec") == "dec":
        # 解密
        n = len(s)
        pattern = list(range(r)) + list(range(r - 2, 0, -1))
        idx = [pattern[i % len(pattern)] for i in range(n)]
        order = sorted(range(n), key=lambda i: (idx[i], i))
        res = [""] * n
        for pos, i in enumerate(order):
            res[i] = s[pos]
        return ok("".join(res))
    pattern = list(range(r)) + list(range(r - 2, 0, -1))
    rows = [""] * r
    for i, ch in enumerate(s):
        rows[pattern[i % len(pattern)]] += ch
    out, idx = [], [pattern[i % len(pattern)] for i in range(len(s))]
    ptr = [0] * r
    for k in idx:
        out.append(rows[k][ptr[k]])
        ptr[k] += 1
    return ok("".join(out))


def t_substitution(f):
    s = str(f.get("data") or "")
    letters = "".join(c.lower() for c in s if c.isalpha())
    if len(letters) < 120:
        raise ValueError("明文太短 (建议 ≥ 200 字母), 爬山法难以收敛")
    alpha = "abcdefghijklmnopqrstuvwxyz"
    eng = "etaoinshrdlucmfwypvbgkjqxz"          # 英文字母频率序
    # 密文字母按出现频率排序 → 与英文频率序对齐, 作为优质初值
    freq = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    by_freq = sorted(alpha, key=lambda c: -freq.get(c, 0))
    m0 = dict(zip(by_freq, eng))

    def enc(mm):
        return "".join(mm.get(c, c) for c in letters)

    rng = random.Random(20261026)
    best_map, best_score = dict(m0), qscore(enc(m0))
    for r in range(6):                          # 频率初值 + 5 次扰动重启
        if r == 0:
            m = dict(m0)
        else:
            perm = list(alpha)
            rng.shuffle(perm)
            m = dict(zip(alpha, perm))
        cur = qscore(enc(m))
        for _ in range(3000):
            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue
            ca, cb = alpha[a], alpha[b]
            m[ca], m[cb] = m[cb], m[ca]
            sc = qscore(enc(m))
            if sc > cur:
                cur = sc
            else:
                m[ca], m[cb] = m[cb], m[ca]
        if cur > best_score:
            best_score, best_map = cur, dict(m)
    out = "".join(best_map.get(c, c) if c.isalpha() else c for c in s.lower())
    mapping = " ".join(f"{k}->{v}" for k, v in sorted(best_map.items()))
    return ok(out, [("四元组评分", round(best_score, 4)), ("映射", mapping)])


# ======================================================================
# XOR 工具
# ======================================================================

def _score_bytes(b):
    return ctfk.chi2_english(b.decode("latin-1"))


def t_xor_single(f):
    data = pbytes(f.get("data"), f.get("is_hex", "1") == "1")
    rows = []
    for k in range(256):
        p = bytes(c ^ k for c in data)
        rows.append((-xor_score(p.decode("latin-1")), k, p))
    rows.sort()
    lines = [f"[key=0x{k:02x} score={sc:9.3f}] {pstr(p)[:140]}" for sc, k, p in rows[:6]]
    return ok("\n".join(lines))


def t_xor_repeat(f):
    data = pbytes(f.get("data"), True)
    forced = f.get("keylen")

    def decrypt(key):
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

    def keyscore(key):
        return xor_score(decrypt(key).decode("latin-1"))

    if forced:
        lens = [pint(forced)]
    else:
        cand = []
        for L in range(2, min(41, max(3, len(data) // 3))):
            chunks = [data[i:i + L] for i in range(0, len(data) - L, L)]
            if len(chunks) < 2:
                continue
            ds = [ctfk.hamming_bits(chunks[i], chunks[i + 1]) / L
                  for i in range(len(chunks) - 1)]
            cand.append((sum(ds) / len(ds), L))
        cand.sort()
        lens = [L for _, L in cand[:12]] or [2]

    # 每个候选长度: 列频率卡方定初值 → 按初值评分排序 → top3 用四元组爬山精修
    inits = []
    for L in lens:
        key = bytearray()
        for i in range(L):
            col = data[i::L]
            key.append(min(range(256), key=lambda k: ctfk.chi2_english(
                bytes(x ^ k for x in col).decode("latin-1"))))
        inits.append((keyscore(bytes(key)), L, bytearray(key)))
    inits.sort(key=lambda x: -x[0])

    best = None
    for sc0, L, key in inits[:3]:
        if len(data) * L <= 120000:              # 爬山精修 (控制规模)
            cur = sc0
            for _ in range(3):
                changed = False
                for pos in range(L):
                    bk, bs = key[pos], cur
                    for k in range(256):
                        if k == key[pos]:
                            continue
                        key[pos] = k
                        sc = keyscore(bytes(key))
                        if sc > bs:
                            bs, bk = sc, k
                    key[pos] = bk
                    if bs > cur:
                        cur, changed = bs, True
                if not changed:
                    break
        sc = keyscore(bytes(key))
        if best is None or sc > best[0]:
            best = (sc, bytes(key))
    score, key = best
    # 周期约简 (周期密钥等价, 展示更干净)
    for per in range(1, len(key)):
        if all(key[i] == key[i % per] for i in range(len(key))):
            trial = bytes(key[:per])
            s2 = keyscore(trial)
            if abs(s2 - score) < 1e-6:
                key, score = trial, s2
            break
    return ok(pstr(decrypt(key)), [("密钥长度", len(key)), ("密钥(hex)", key.hex()),
                                   ("评测分", round(score, 3)),
                                   ("提示", "密文过短时请手动指定密钥长度")])


def t_xor_known(f):
    ct = pbytes(f.get("ct"), True)
    pt = pbytes(f.get("pt"), f.get("pt_hex", "0") == "1")
    ks = ctfk.xor_bytes(ct[:len(pt)], pt)
    return ok(ks.hex(), [("密钥流长度", len(ks))])


def t_xor_two(f):
    a = pbytes(f.get("c1"), True)
    b = pbytes(f.get("c2"), True)
    return ok(pstr(ctfk.xor_bytes(a, b)), [("长度", min(len(a), len(b)))])


# ======================================================================
# 哈希工具
# ======================================================================

def _leet(w: bytes) -> bytes:
    tr = {ord("a"): b"@", ord("e"): b"3", ord("i"): b"1", ord("o"): b"0",
          ord("s"): b"$", ord("t"): b"7"}
    return b"".join(tr.get(c, bytes([c])) for c in w)


def _variants(w: bytes):
    yield w
    yield w.capitalize()
    yield _leet(w)
    yield w + b"123"
    yield w + b"!"
    for y in (b"2024", b"2025", b"2026"):
        yield w + y


def t_hash(f):
    data = pbytes(f.get("data"), f.get("is_hex") == "1")
    return ok("\n".join([
        "md5    " + hashlib.md5(data).hexdigest(),
        "sha1   " + hashlib.sha1(data).hexdigest(),
        "sha256 " + hashlib.sha256(data).hexdigest(),
        "sha512 " + hashlib.sha512(data).hexdigest(),
        "crc32  " + format(zlib.crc32(data), "08x"),
    ]), [("输入长度", f"{len(data)} 字节")])


def t_hash_crack(f):
    import resources as RES
    target = re.sub(r"\s", "", str(f.get("hash") or "")).lower()
    algo = f.get("algo", "md5")
    limit = max(1000, min(int(pint(f.get("limit"), 200000)), 5000000))
    rules = f.get("rules") == "1"
    res = RES.get_resources()
    if algo == "ntlm":
        from Crypto.Hash import MD4
        def hfun(w):
            h = MD4.new()
            h.update(w.decode("latin-1").encode("utf-16-le"))
            return h.hexdigest()
    else:
        hfun = lambda w: hashlib.new(algo, w).hexdigest()  # noqa: E731
    hit, tried = None, 0
    t0 = time.time()
    if res.get("rockyou"):
        for w in RES.rockyou_iter(res, limit=limit):
            tried += 1
            if hfun(w) == target:
                hit = (w, "rockyou")
                break
            if rules:
                for v in _variants(w):
                    tried += 1
                    if hfun(v) == target:
                        hit = (v, "rockyou+规则")
                        break
                if hit:
                    break
            if time.time() - t0 > 25:
                break
    else:
        wl = LAB / "lib" / "data" / "wordlist.txt"
        if wl.exists():
            for line in wl.read_text(encoding="utf-8", errors="ignore").splitlines():
                w = line.strip().encode()
                if not w:
                    continue
                tried += 1
                for v in (_variants(w) if rules else (w,)):
                    if hfun(v) == target:
                        hit = (v, "内置词表")
                        break
                if hit:
                    break
    if hit:
        return ok(hit[0].decode("latin-1"), [("算法", algo), ("来源", hit[1]),
                                            ("尝试次数", f"{tried:,}"),
                                            ("耗时", f"{time.time() - t0:.2f}s")])
    return ok(f"(未命中: 尝试 {tried:,} 条, {time.time() - t0:.2f}s)",
              [("提示", "可提高上限 / 勾选规则变形 / 换算法")])


def t_len_ext(f):
    digest = bytes.fromhex(re.sub(r"\s", "", str(f.get("digest") or "")))
    plen = pint(f.get("prefix_len"), 0)
    suffix = pbytes(f.get("suffix"))
    appendix, new_digest = ctfk.md5_lenext(digest, plen, suffix)
    return ok(f"新消息追加部分 (hex):\n{appendix.hex()}\n\n新 MAC:\n{new_digest.hex()}",
              [("追加部分长度", len(appendix)), ("其中 glue padding", len(ctfk.md5_pad(plen))),
               ("可打印后缀", suffix.decode("latin-1"))])


def t_crc_patch(f):
    prefix = pbytes(f.get("prefix"), f.get("is_hex") == "1")
    target = pint(f.get("target"))
    suffix = ctfk.crc32_patch(prefix, target & 0xFFFFFFFF)
    if suffix is None:
        return fail("无解 (CRC32 4 字节补丁应总有解, 请检查输入)")
    return ok(suffix.hex(), [("原始 CRC", format(zlib.crc32(prefix), "08x")),
                             ("伪造后 CRC", format(zlib.crc32(prefix + suffix), "08x"))])


# ======================================================================
# 数论 / RSA
# ======================================================================

def t_nt(f):
    op = f.get("op", "gcd")
    a, b = f.get("a"), f.get("b")
    if op == "gcd":
        return ok(big(math.gcd(pint(a), pint(b))))
    if op == "lcm":
        x, y = pint(a), pint(b)
        return ok(big(abs(x * y) // math.gcd(x, y)))
    if op == "modinv":
        return ok(big(ctfk.modinv(pint(a), pint(b))))
    if op == "iroot":
        return ok(big(ctfk.iroot(pint(a), pint(b, 2))))
    if op == "is_prime":
        return ok("是素数" if ctfk.is_prime(pint(a)) else "合数")
    if op == "factorint":
        fac = ctfk.factorint(pint(a))
        lines = [f"{p}^{e}" if e > 1 else str(p) for p, e in fac.items()]
        chk = 1
        for p, e in fac.items():
            chk *= p ** e
        return ok(" × ".join(lines), [("验证", "✔ 乘积一致" if chk == pint(a) else "✘ 不一致")])
    if op == "powmod":
        return ok(big(pow(pint(a), pint(b), pint(f.get("c")))))
    if op == "bytes2int":
        return ok(big(int.from_bytes(pbytes(a), "big")))
    if op == "int2bytes":
        v = pint(a)
        return ok(pstr(v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")))
    raise ValueError("未知操作")


def t_rsa_basic(f):
    p, q = pint(f.get("p")), pint(f.get("q"))
    e = pint(f.get("e"), 65537)
    c = pint(f.get("c"))
    n = p * q
    phi = (p - 1) * (q - 1)
    d = ctfk.modinv(e, phi)
    m = pow(c, d, n)
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("n", big(n)), ("phi", big(phi)), ("d", big(d)), ("m (int)", big(m))])


def t_rsa_factor(f):
    n = pint(f.get("n"))
    t0 = time.time()
    if ctfk.is_prime(n):
        return ok("n 是素数")
    fac = ctfk.factorint(n)
    chk = 1
    for p, e in fac.items():
        chk *= p ** e
    lines = [f"{p}^{e}" if e > 1 else str(p) for p, e in fac.items()]
    return ok(" × ".join(lines), [("验证", "✔" if chk == n else "✘"),
                                  ("耗时", f"{time.time() - t0:.2f}s")])


def t_rsa_common(f):
    n = pint(f.get("n"))
    e1, e2 = pint(f.get("e1")), pint(f.get("e2"))
    c1, c2 = pint(f.get("c1")), pint(f.get("c2"))
    g, s1, s2 = _egcd(e1, e2)
    if g != 1:
        return fail(f"gcd(e1,e2)={g} ≠ 1, 共模攻击不适用")
    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("扩展欧几里得", f"{s1}·e1 + {s2}·e2 = 1"),
                        ("m (int)", big(m))])


def t_rsa_broadcast(f):
    e = pint(f.get("e"), 3)
    lines = [l for l in str(f.get("pairs") or "").splitlines() if l.strip()]
    pairs = []
    for ln in lines:
        nums = _split_ints(ln)
        if len(nums) >= 2:
            pairs.append((nums[0], nums[1]))
    if len(pairs) < e:
        return fail(f"需要至少 e={e} 组 (n, c)")
    r, M = ctfk.crt([(c, n) for n, c in pairs[:e]])
    m = ctfk.iroot(r, e)
    if m ** e != r:
        return fail("开根不精确 —— 明文可能 ≥ n 或分组不足")
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("CRT 模数位数", M.bit_length()), ("m (int)", big(m))])


def t_rsa_small_e(f):
    e = pint(f.get("e"), 3)
    c = pint(f.get("c"))
    m = ctfk.iroot(c, e)
    exact = m ** e == c
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("整数根精确", "✔" if exact else "✘ (存在模约简, 需其他攻击)")])


def t_rsa_shared(f):
    n1, n2 = pint(f.get("n1")), pint(f.get("n2"))
    e = pint(f.get("e"), 65537)
    c = pint(f.get("c"))
    p = math.gcd(n1, n2)
    if p == 1:
        return fail("两模数无公共因子")
    q = n1 // p
    d = ctfk.modinv(e, (p - 1) * (q - 1))
    m = pow(c, d, n1)
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("共享素数 p", big(p))])


def t_rsa_wiener(f):
    n, e = pint(f.get("n")), pint(f.get("e"))
    t0 = time.time()
    d = ctfk.wiener(e, n)
    if not d:
        return fail("Wiener 攻击失败 (d 不够小)")
    c = f.get("c")
    extras = [("恢复的 d", big(d)), ("耗时", f"{time.time() - t0:.2f}s")]
    if c:
        m = pow(pint(c), d, n)
        extras.append(("解出的 m", big(m)))
        return ok(pstr(m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")), extras)
    return ok(big(d), extras)


def t_rsa_fermat(f):
    n = pint(f.get("n"))
    t0 = time.time()
    r = ctfk.fermat_factor(n, max_steps=1 << 20)
    if not r:
        return fail("Fermat 分解失败 (p, q 差距过大)")
    p, q = r
    return ok(f"p = {big(p)}\nq = {big(q)}", [("耗时", f"{time.time() - t0:.2f}s")])


def t_rsa_franklin(f):
    n, e = pint(f.get("n")), pint(f.get("e"), 3)
    c1, c2 = pint(f.get("c1")), pint(f.get("c2"))
    delta = pint(f.get("delta"), 1)
    # g1 = x^e - c1 ; g2 = (x+d)^e - c2
    d = delta
    poly2 = [d ** e - c2]
    for k in range(1, e + 1):
        import math as _m
        poly2.append(_m.comb(e, k) * d ** (e - k))
    g, fac = ctfk.poly_gcd_modn([(-c1) % n] + [0] * (e - 1) + [1], poly2, n)
    if fac:
        return ok(f"顺手分解出因子: {fac}", [("说明", "多项式 gcd 遇到不可逆首项")])
    if not g or len(g) != 2:
        return fail("多项式 gcd 不是一次式 —— 检查 e 与 c1/c2 是否自洽")
    m = (-g[0] * ctfk.modinv(g[1], n)) % n
    b = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return ok(pstr(b), [("m (int)", big(m)), ("gcd 多项式", str(g))])


def t_rsa_coppersmith(f):
    n = pint(f.get("n"))
    p_high = pint(f.get("p_high"))
    bits = pint(f.get("unknown_bits"), 48)
    beta = float(f.get("beta") or 0.5)
    m = int(pint(f.get("m"), 0)) or None
    t = int(pint(f.get("t"), 0)) or None
    X = 1 << bits
    base = p_high << bits
    t0 = time.time()
    if m is None:
        m = max(3, int(0.5 * beta * beta * n.bit_length() / max(1, bits)))
    if t is None:
        t = m
    roots = ctfk.small_roots([base, 1], n, beta, X, m=m, t=t)
    dt = time.time() - t0
    if not roots:
        return fail(f"未找到小根 (m={m}, t={t}, 耗时 {dt:.1f}s) —— 可尝试增大 m/t 或检查高位/位数")
    p = base + roots[0]
    extras = [("根", roots), ("p", big(p)), ("耗时", f"{dt:.1f}s"), ("m/t", f"{m}/{t}")]
    if n % p == 0:
        q = n // p
        extras.append(("q", big(q)))
        if f.get("e") and f.get("c"):
            e = pint(f.get("e"))
            d = ctfk.modinv(e, (p - 1) * (q - 1))
            mm = pow(pint(f.get("c")), d, n)
            return ok(pstr(mm.to_bytes((mm.bit_length() + 7) // 8 or 1, "big")), extras)
    return ok(big(p), extras)


# ======================================================================
# 离散对数 / EC
# ======================================================================

def t_dlog(f):
    p, g, h = pint(f.get("p")), pint(f.get("g")), pint(f.get("h"))
    mode = f.get("mode", "bsgs")
    t0 = time.time()
    if mode == "bsgs":
        x = ctfk.bsgs(g, h, p, pint(f.get("order"), p - 1))
        if x is None:
            return fail("BSGS 未找到解 (检查 order)")
        return ok(big(x), [("验证", f"g^x ≡ h ? {pow(g, x, p) == h % p}"),
                           ("耗时", f"{time.time() - t0:.2f}s")])
    fac = ctfk.factorint(p - 1)
    x = ctfk.pohlig_hellman(g, h, p, fac)
    if x is None:
        return fail("Pohlig-Hellman 失败")
    return ok(big(x), [("p-1 分解", " × ".join(f"{q}^{e}" if e > 1 else str(q) for q, e in fac.items())),
                       ("验证", f"g^x ≡ h ? {pow(g, x, p) == h % p}"),
                       ("耗时", f"{time.time() - t0:.2f}s")])


def t_ec(f):
    p, a, b = pint(f.get("p")), pint(f.get("a"), 0), pint(f.get("b"))
    E = ctfk.EC(a, b, p)
    op = f.get("op", "mul")
    P = (pint(f.get("px")), pint(f.get("py")))
    R = None
    if op == "on":
        return ok("点在曲线上 ✔" if E.on(P) else "点不在曲线上 ✘")
    if op == "mul":
        R = E.mul(pint(f.get("k"), 2), P)
    elif op == "add":
        Q = (pint(f.get("qx")), pint(f.get("qy")))
        R = E.add(P, Q)
    elif op == "dlog":
        Q = (pint(f.get("qx")), pint(f.get("qy")))
        order = pint(f.get("order"), 0) or None
        if not order:
            return fail("ECDLP 需要提供点的阶 order")
        k = E.ec_bsgs(P, Q, order)
        return ok(big(k) if k is not None else "未找到", [("order", order)])
    return ok("无穷远点 O" if R is None else f"({R[0]}, {R[1]})",
              [("验证在曲线上", "✔" if E.on(R) else "✘")])


# ======================================================================
# PRNG
# ======================================================================

def t_mt(f):
    outs = _split_ints(f.get("outputs"))
    n = int(pint(f.get("n"), 5))
    if len(outs) < 624:
        return fail(f"需要 624 个连续 32 位输出 (当前 {len(outs)})")
    gen = ctfk.clone_mt([x & 0xFFFFFFFF for x in outs[:624]])
    nxt = [gen.next32() for _ in range(n)]
    return ok("\n".join(format(x, "x") for x in nxt),
              [("输出(decimal)", ", ".join(str(x) for x in nxt)),
               ("说明", "已克隆状态, 上述为后续输出 (hex)")])


def t_lcg_params(f):
    outs = _split_ints(f.get("outputs"))
    if len(outs) < 6:
        return fail("需要 ≥ 6 个连续完整输出")
    r = ctfk.solve_lcg_params(outs)
    if not r:
        return fail("参数恢复失败 (输出不连续或含截断)")
    m, a, c = r
    nxt = (a * outs[-1] + c) % m
    return ok(f"m = {big(m)}\na = {big(a)}\nc = {big(c)}",
              [("下个输出", big(nxt))])


def t_lcg_trunc(f):
    m = pint(f.get("m"))
    a, c = pint(f.get("a")), pint(f.get("c"))
    shift = pint(f.get("shift"), 32)
    highs = _split_ints(f.get("highs"))
    states = ctfk.solve_lcg_truncated(m, a, c, highs, shift)
    if not states:
        return fail("格恢复失败 (样本不足或参数不匹配)")
    return ok("\n".join(str(s) for s in states),
              [("说明", "恢复的完整状态序列 (十进制)"),
               ("后续预测", ", ".join(str((a * states[-1] + c) % m)))])


# ======================================================================
# 格
# ======================================================================

def t_hnp(f):
    p = pint(f.get("p"))
    B = pint(f.get("B"))
    samples = []
    for ln in str(f.get("samples") or "").splitlines():
        nums = _split_ints(ln)
        if len(nums) >= 2:
            samples.append((nums[0], nums[1]))
    if len(samples) < 3:
        return fail("需要至少 3 行 (a, c) 样本")
    t0 = time.time()
    x = ctfk.solve_hnp(samples, p, B)
    if x is None:
        return fail(f"未恢复 (样本数 {len(samples)}, 耗时 {time.time() - t0:.1f}s) —— 增加样本或检查 B")
    return ok(big(x), [("样本数", len(samples)), ("验证",
                        all(abs(((a * x - c) % p + p // 2) % p - p // 2) < B for a, c in samples)),
                       ("耗时", f"{time.time() - t0:.1f}s")])


def t_knapsack(f):
    pub = _split_ints(f.get("pubkey"))
    s = pint(f.get("s"))
    n = len(pub)
    if n < 4:
        return fail("公钥长度至少 4")
    rows = []
    for i in range(n):
        row = [2 if j == i else 0 for j in range(n)] + [2 * pub[i]]
        rows.append(row)
    rows.append([1] * n + [2 * s])
    red = ctfk.lll(rows)
    for vec in red:
        if vec[n] != 0:
            continue
        v = vec[:n]
        if all(x in (-1, 1) for x in v):
            for sgn in (1, -1):
                bits = [1 if sgn * x == 1 else 0 for x in v]
                if sum(b * p for b, p in zip(bits, pub)) == s:
                    body = bytes(int("".join(map(str, bits[i:i + 8])), 2)
                                 for i in range(0, n - 7, 8))
                    return ok(pstr(body), [("比特串", "".join(map(str, bits))),
                                           ("说明", "每 8 位一个字节")])
    return fail("CJLOSS 未解出 (可能密度过高)")


# ======================================================================
# 工具表
# ======================================================================

def F(name, label, **kw):
    d = {"name": name, "label": label, "type": kw.pop("type", "text"),
         "default": kw.pop("default", ""), "placeholder": kw.pop("placeholder", ""),
         "help": kw.pop("help", ""), "options": kw.pop("options", None),
         "rows": kw.pop("rows", 6)}
    d.update(kw)
    return d


SEL = lambda name, label, opts, default: F(name, label, type="select",  # noqa: E731
                                          options=[{"v": v, "l": l} for v, l in opts],
                                          default=default)

TOOLS = [
    # ---- 编码 ----
    {"id": "auto", "group": "编码", "name": "自动剥壳", "desc": "递归识别 hex/base32/base64/ascii85",
     "fields": [F("data", "数据", type="textarea", rows=8),
                SEL("is_hex", "输入格式", [("0", "文本"), ("1", "Hex")], "0")],
     "fn": t_auto},
    {"id": "hex", "group": "编码", "name": "Hex 编解码", "desc": "文本 ↔ 十六进制",
     "fields": [SEL("mode", "方向", [("dec", "解码 Hex → 文本"), ("enc", "编码 文本 → Hex")], "dec"),
                F("data", "数据", type="textarea", rows=6)],
     "fn": t_hex},
    {"id": "base", "group": "编码", "name": "Base 编解码", "desc": "Base64 / 32 / 85 / urlsafe",
     "fields": [SEL("mode", "方向", [("dec", "解码"), ("enc", "编码")], "dec"),
                SEL("scheme", "Base", [("64", "Base64"), ("64url", "Base64 URL-safe"),
                                       ("32", "Base32"), ("85", "Ascii85")], "64"),
                F("data", "数据", type="textarea", rows=6)],
     "fn": t_base},
    {"id": "url", "group": "编码", "name": "URL 解码", "desc": "%xx 百分号编码还原",
     "fields": [F("data", "数据", type="textarea", rows=4)], "fn": t_url},
    {"id": "caesar", "group": "编码", "name": "凯撒移位", "desc": "加密/解密/26 种爆破",
     "fields": [SEL("mode", "模式", [("brute", "爆破 (评分排序)"), ("dec", "解密"), ("enc", "加密")], "brute"),
                F("shift", "位移", default="3"), F("data", "密文 / 明文", type="textarea", rows=5)],
     "fn": t_caesar},
    {"id": "morse", "group": "编码", "name": "摩斯电码", "desc": "摩斯 ↔ 文本 (空格分词, / 分字)",
     "fields": [SEL("mode", "方向", [("dec", "摩斯 → 文本"), ("enc", "文本 → 摩斯")], "dec"),
                F("data", "数据", type="textarea", rows=4, placeholder=".... .. / -.-. -.-. - ..-. ...")],
     "fn": t_morse},

    # ---- 古典 ----
    {"id": "vigenere", "group": "古典", "name": "维吉尼亚", "desc": "加解密 + IC 自动破译",
     "fields": [SEL("mode", "模式", [("crack", "自动破译"), ("dec", "解密"), ("enc", "加密")], "crack"),
                F("key", "密钥 (自动破译时留空)", placeholder="key"),
                F("data", "数据", type="textarea", rows=6)],
     "fn": t_vigenere},
    {"id": "affine", "group": "古典", "name": "仿射密码", "desc": "312 种密钥全爆破 + 英文评分",
     "fields": [F("data", "密文", type="textarea", rows=6)], "fn": t_affine},
    {"id": "playfair", "group": "古典", "name": "Playfair", "desc": "5×5 方阵加解密",
     "fields": [SEL("mode", "方向", [("dec", "解密"), ("enc", "加密")], "dec"),
                F("key", "密钥", default="monarchy"), F("data", "数据", type="textarea", rows=5)],
     "fn": t_playfair},
    {"id": "hill", "group": "古典", "name": "Hill 密码", "desc": "矩阵解密 / 已知明文恢复密钥",
     "fields": [SEL("mode", "模式", [("dec", "解密 (给密钥)"), ("kpa", "已知明文恢复密钥")], "dec"),
                F("key", "密钥矩阵 (按行 9 个数)", placeholder="3 5 1 2"),
                F("pt", "已知明文 (kpa)", type="textarea", rows=3),
                F("ct", "已知密文 (kpa)", type="textarea", rows=3),
                F("data", "待解密密文", type="textarea", rows=5)],
     "fn": t_hill},
    {"id": "railfence", "group": "古典", "name": "栅栏密码", "desc": "W 型栅栏加解密",
     "fields": [SEL("mode", "方向", [("dec", "解密"), ("enc", "加密")], "dec"),
                F("rails", "栏数", default="3"), F("data", "数据", type="textarea", rows=5)],
     "fn": t_railfence},
    {"id": "substitution", "group": "古典", "name": "单表替代破译", "desc": "bigram 爬山法 (需 ≥200 字母)",
     "fields": [F("data", "密文", type="textarea", rows=8)], "fn": t_substitution},

    # ---- XOR ----
    {"id": "xor-single", "group": "XOR", "name": "单字节 XOR 爆破", "desc": "256 种密钥按英文评分",
     "fields": [F("data", "密文", type="textarea", rows=5),
                SEL("is_hex", "格式", [("1", "Hex"), ("0", "文本")], "1")],
     "fn": t_xor_single},
    {"id": "xor-repeat", "group": "XOR", "name": "重复密钥 XOR 破译", "desc": "汉明距离猜长度 + 分列频率",
     "fields": [F("data", "密文 (hex)", type="textarea", rows=6),
                F("keylen", "密钥长度 (可空, 自动 2~40)")],
     "fn": t_xor_repeat},
    {"id": "xor-known", "group": "XOR", "name": "已知明文求密钥流", "desc": "keystream = ct XOR pt",
     "fields": [F("ct", "密文 (hex)", type="textarea", rows=4),
                F("pt", "已知明文", type="textarea", rows=4),
                SEL("pt_hex", "明文格式", [("0", "文本"), ("1", "Hex")], "0")],
     "fn": t_xor_known},
    {"id": "xor-two", "group": "XOR", "name": "双密文异或", "desc": "同密钥流重用的两条密文",
     "fields": [F("c1", "密文 1 (hex)", type="textarea", rows=4),
                F("c2", "密文 2 (hex)", type="textarea", rows=4)],
     "fn": t_xor_two},

    # ---- 哈希 ----
    {"id": "hash", "group": "哈希", "name": "哈希计算", "desc": "md5/sha1/sha256/sha512/crc32",
     "fields": [F("data", "数据", type="textarea", rows=5),
                SEL("is_hex", "格式", [("0", "文本"), ("1", "Hex")], "0")], "fn": t_hash},
    {"id": "hash-crack", "group": "哈希", "name": "字典破解哈希", "desc": "rockyou + 规则变形",
     "fields": [F("hash", "目标哈希 (hex)", type="textarea", rows=2),
                SEL("algo", "算法", [("md5", "MD5"), ("sha1", "SHA1"), ("sha256", "SHA256"),
                                     ("ntlm", "NTLM")], "md5"),
                F("limit", "字典上限 (行)", default="200000"),
                SEL("rules", "规则变形", [("0", "关闭"), ("1", "开启 (大小写/leet/后缀)")], "0")],
     "fn": t_hash_crack},
    {"id": "len-ext", "group": "哈希", "name": "MD5 长度扩展", "desc": "已知 MAC 与长度, 追加任意后缀",
     "fields": [F("digest", "原 MAC (hex, 32 字符)", placeholder="79054025255fb1a26e4bc422aef54eb4"),
                F("prefix_len", "原消息总长度 (含 secret)", default="16"),
                F("suffix", "要追加的后缀", default=";admin=true")],
     "fn": t_len_ext},
    {"id": "crc-patch", "group": "哈希", "name": "CRC32 伪造", "desc": "4 字节补丁命中任意 CRC",
     "fields": [F("prefix", "前缀内容", type="textarea", rows=4),
                SEL("is_hex", "前缀格式", [("0", "文本"), ("1", "Hex")], "0"),
                F("target", "目标 CRC32 (hex 或 dec)", placeholder="deadbeef")],
     "fn": t_crc_patch},

    # ---- 数论 / RSA ----
    {"id": "nt", "group": "数论/RSA", "name": "数论工具", "desc": "gcd/modinv/分解/开根/进制转换",
     "fields": [SEL("op", "操作", [("gcd", "gcd(a,b)"), ("lcm", "lcm(a,b)"),
                                   ("modinv", "a⁻¹ mod b"), ("iroot", "⌊a^(1/b)⌋"),
                                   ("is_prime", "素性检测 a"), ("factorint", "分解 a"),
                                   ("powmod", "a^b mod c"), ("bytes2int", "bytes → int"),
                                   ("int2bytes", "int → bytes")], "gcd"),
                F("a", "a"), F("b", "b"), F("c", "c (powmod)")], "fn": t_nt},
    {"id": "rsa-basic", "group": "数论/RSA", "name": "RSA 解密", "desc": "已知 p,q,e,c 求明文",
     "fields": [F("p", "p"), F("q", "q"), F("e", "e", default="65537"),
                F("c", "c", type="textarea", rows=2)], "fn": t_rsa_basic},
    {"id": "rsa-factor", "group": "数论/RSA", "name": "分解 n", "desc": "试除 + Pollard rho",
     "fields": [F("n", "n", type="textarea", rows=2)], "fn": t_rsa_factor},
    {"id": "rsa-common", "group": "数论/RSA", "name": "共模攻击", "desc": "同 n 双指数, gcd(e1,e2)=1",
     "fields": [F("n", "n", type="textarea", rows=2), F("e1", "e1"), F("e2", "e2"),
                F("c1", "c1", type="textarea", rows=2), F("c2", "c2", type="textarea", rows=2)],
     "fn": t_rsa_common},
    {"id": "rsa-broadcast", "group": "数论/RSA", "name": "广播攻击 (Håstad)", "desc": "e 组同明文不同模数",
     "fields": [F("e", "e", default="3"),
                F("pairs", "每行一组: n c", type="textarea", rows=6,
                  placeholder="n1 c1\nn2 c2\nn3 c3")], "fn": t_rsa_broadcast},
    {"id": "rsa-small-e", "group": "数论/RSA", "name": "小指数开根", "desc": "m^e < n 时直接开根",
     "fields": [F("e", "e", default="3"), F("c", "c", type="textarea", rows=2)],
     "fn": t_rsa_small_e},
    {"id": "rsa-shared", "group": "数论/RSA", "name": "共享素数", "desc": "gcd(n1,n2) 直接分解",
     "fields": [F("n1", "n1", type="textarea", rows=2), F("n2", "n2", type="textarea", rows=2),
                F("e", "e", default="65537"), F("c", "c (用 n1 加密)", type="textarea", rows=2)],
     "fn": t_rsa_shared},
    {"id": "rsa-wiener", "group": "数论/RSA", "name": "Wiener 攻击", "desc": "小私钥 d 的连分数攻击",
     "fields": [F("n", "n", type="textarea", rows=2), F("e", "e", type="textarea", rows=2),
                F("c", "c (可选, 给了就顺便解密)", type="textarea", rows=2)], "fn": t_rsa_wiener},
    {"id": "rsa-fermat", "group": "数论/RSA", "name": "Fermat 分解", "desc": "p、q 相近时高效",
     "fields": [F("n", "n", type="textarea", rows=2)], "fn": t_rsa_fermat},
    {"id": "rsa-franklin", "group": "数论/RSA", "name": "Franklin-Reiter", "desc": "相关消息 m 与 m+δ",
     "fields": [F("n", "n", type="textarea", rows=2), F("e", "e", default="3"),
                F("c1", "c1", type="textarea", rows=2), F("c2", "c2", type="textarea", rows=2),
                F("delta", "δ (m2 = m1 + δ)", default="1")], "fn": t_rsa_franklin},
    {"id": "rsa-coppersmith", "group": "数论/RSA", "name": "Coppersmith 已知高位", "desc": "由 p 的高位补全低位 (较慢)",
     "fields": [F("n", "n", type="textarea", rows=2),
                F("p_high", "p 的高位 (整数)", type="textarea", rows=2),
                F("unknown_bits", "未知低位比特数", default="48"),
                F("beta", "beta", default="0.5"),
                F("m", "格参数 m (空=自动)"), F("t", "格参数 t (空=自动)"),
                F("e", "e (可选)"), F("c", "c (可选, 自动解密)")],
     "fn": t_rsa_coppersmith},

    # ---- 离散对数 ----
    {"id": "dlog", "group": "离散对数", "name": "离散对数", "desc": "BSGS / Pohlig-Hellman",
     "fields": [F("p", "模数 p"), F("g", "生成元 g"), F("h", "目标 h"),
                SEL("mode", "算法", [("bsgs", "BSGS (大步小步)"), ("pohlig", "Pohlig-Hellman")], "bsgs"),
                F("order", "ord(g) (BSGS 可空)")], "fn": t_dlog},
    {"id": "ec", "group": "离散对数", "name": "椭圆曲线", "desc": "点加/标量乘/ECDLP",
     "fields": [F("p", "p"), F("a", "a", default="0"), F("b", "b", default="7"),
                SEL("op", "操作", [("mul", "k·P"), ("add", "P + Q"), ("on", "点是否在曲线上"),
                                   ("dlog", "ECDLP (BSGS)")], "mul"),
                F("px", "P.x"), F("py", "P.y"), F("k", "k (mul)", default="2"),
                F("qx", "Q.x"), F("qy", "Q.y"), F("order", "ord(P) (dlog 必填)")],
     "fn": t_ec},

    # ---- PRNG ----
    {"id": "mt", "group": "PRNG", "name": "MT19937 克隆", "desc": "624 个输出后预测未来",
     "fields": [F("outputs", "624 个连续 32 位输出 (空白分隔)", type="textarea", rows=8),
                F("n", "预测个数", default="5")], "fn": t_mt},
    {"id": "lcg-params", "group": "PRNG", "name": "LCG 参数恢复", "desc": "≥6 个连续输出还原 m,a,c",
     "fields": [F("outputs", "连续输出 (空白/逗号分隔)", type="textarea", rows=5)],
     "fn": t_lcg_params},
    {"id": "lcg-trunc", "group": "PRNG", "name": "截断 LCG 恢复", "desc": "已知 m,a,c 与高位, 格恢复",
     "fields": [F("m", "m"), F("a", "a"), F("c", "c"),
                F("shift", "未知低位比特数", default="32"),
                F("highs", "各输出的高位值", type="textarea", rows=6)], "fn": t_lcg_trunc},

    # ---- 格 ----
    {"id": "hnp", "group": "格", "name": "隐数问题 HNP", "desc": "a·x - e ≡ c (mod p), |e| < B",
     "fields": [F("p", "模数 p"), F("B", "误差上界 B (整数)"),
                F("samples", "每行一组: a c", type="textarea", rows=8,
                  placeholder="a1 c1\na2 c2\n…")], "fn": t_hnp},
    {"id": "knapsack", "group": "格", "name": "背包格攻击", "desc": "低密度子集和 (CJLOSS)",
     "fields": [F("pubkey", "公钥序列 (空白分隔)", type="textarea", rows=3),
                F("s", "目标和 s")], "fn": t_knapsack},
]

TOOL_MAP = {t["id"]: t for t in TOOLS}
GROUPS = []
for _t in TOOLS:
    if _t["group"] not in GROUPS:
        GROUPS.append(_t["group"])

EXAMPLES = {
    "auto": {"data": "666c61677b6175746f5f6465636f64657d", "is_hex": "0"},
    "caesar": {"mode": "brute", "data": "IODJ{FDHVDU_ZRUNV}", "shift": "3"},
    "vigenere": {"mode": "crack", "data": "RIJVS{...}"},
    "hash": {"data": "flag{hello}", "is_hex": "0"},
    "len-ext": {"digest": "79054025255fb1a26e4bc422aef54eb4", "prefix_len": "16",
                "suffix": ";admin=true"},
    "crc-patch": {"prefix": "Dear admin, please unban user guest.", "is_hex": "0",
                  "target": "deadbeef"},
    "nt": {"op": "factorint", "a": "2500000000000000000000000000000"},
    "mt": {"outputs": "(把你的 624 个输出粘进来)", "n": "5"},
    "hnp": {"p": "", "B": "", "samples": "a1 c1\na2 c2"},
    "knapsack": {"pubkey": "", "s": ""},
}


# ======================================================================
# HTTP
# ======================================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        path = urllib.parse.unquote(self.path.split("?")[0])
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/api/tools":
            items = []
            for t in TOOLS:
                items.append({"id": t["id"], "group": t["group"], "name": t["name"],
                              "desc": t["desc"], "fields": t["fields"],
                              "example": EXAMPLES.get(t["id"])})
            try:
                import resources as RES
                res = RES.get_resources()
            except Exception:
                res = {}
            return self._json({"tools": items, "groups": GROUPS,
                               "resources": {
                                   "rockyou": bool(res.get("rockyou")),
                                   "rockyou_lines": (res.get("rockyou") or {}).get("lines"),
                                   "john": bool(res.get("john")),
                                   "hashcat": bool(res.get("hashcat")),
                               }})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.unquote(self.path)
        m = re.match(r"^/api/tool/([\w\-]+)$", path)
        if not m:
            return self._json({"error": "not found"}, 404)
        tid = m.group(1)
        tool = TOOL_MAP.get(tid)
        if not tool:
            return self._json({"error": "no such tool"}, 404)
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln) if ln else b"{}"
            fields = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
        try:
            res = tool["fn"](fields)
        except Exception as e:  # 工具内部错误 → 友好返回
            res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return self._json(res)


PAGE_RAW = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>密码工具箱 · CTF Crypto Lab</title>
<style>__CSS__
.formcard{max-width:760px}
.resbox{margin-top:18px}
.resbox .out{background:#070b12;border:1px solid var(--line);border-radius:var(--r2);
  padding:12px 14px;font-family:var(--mono);font-size:.84rem;white-space:pre-wrap;
  word-break:break-all;line-height:1.6;max-height:52vh;overflow:auto}
.resbox .hd{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.resbox .badge{font-size:.78rem;padding:2px 9px;border-radius:99px;font-weight:600}
.resbox .badge.ok{background:rgba(52,211,153,.14);color:var(--ok)}
.resbox .badge.bad{background:rgba(248,113,113,.14);color:var(--err)}
.kvgrid{display:grid;grid-template-columns:150px 1fr;gap:5px 14px;margin-top:10px;
  font-size:.82rem;background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r2);padding:10px 14px}
.kvgrid dt{color:var(--dim)}
.kvgrid dd{font-family:var(--mono);word-break:break-all}
.hist{display:flex;flex-direction:column;gap:6px;max-height:32vh;overflow:auto}
.hist .h{display:flex;gap:8px;align-items:center;font-size:.8rem;color:var(--dim);
  border-bottom:1px solid rgba(34,48,77,.6);padding:5px 0;cursor:pointer}
.hist .h:hover{color:var(--txt)}
.hist .h b{color:var(--txt);font-weight:500}
kbd{background:var(--panel2);border:1px solid var(--line2);border-bottom-width:2px;
  border-radius:5px;padding:1px 6px;font-size:.75rem;font-family:var(--mono);color:var(--txt)}
</style>
</head>
<body>
<div class="shell">
  <aside class="side">
    <div class="brand"><span class="dot"></span><div>密码工具箱<small>CTF Crypto Lab · Toolkit</small></div></div>
    <nav class="nav" id="gnav"></nav>
    <div class="grp nav" style="display:block"><div class="grp">导航</div>
      <a href="#/" data-r="home"><span class="ic">◈</span><span class="tx">全部工具</span></a>
      <a href="#/docs" data-r="docs"><span class="ic">📘</span><span class="tx">使用说明</span></a>
      <a href="http://127.0.0.1:8787/" target="_blank" rel="noopener"><span class="ic">🎯</span><span class="tx">题目站 ↗</span></a>
    </div>
    <div class="foot" id="resline">资源: 探测中…</div>
  </aside>
  <div class="main">
    <div class="topbar">
      <div class="title" id="crumb">全部工具</div>
      <div class="sp"></div>
      <div class="tiny muted">Ctrl/⌘ + Enter 运行 · / 搜索</div>
    </div>
    <div class="page" id="view"><div class="empty"><div class="big">◌</div>加载工具…</div></div>
  </div>
</div>
<div id="toast"></div>
<script>__JS__</script>
<script>
let TOOLS=[], GROUPS=[], RES={}, cur=null, curId=null;
const HIST=[];
const ICON={"编码":"⌗","古典":"🏛","XOR":"⊕","哈希":"#","数论/RSA":"🧮","离散对数":"🔑","PRNG":"🎲","格":"🔷"};

function setNav(id){$$("#gnav a, .nav a[data-r]").forEach(a=>{
  a.classList.toggle("on",a.dataset.t===id||a.dataset.r===id);});}

/* ---------- 全部工具 ---------- */
function viewHome(){
  curId=null;setNav("home");$("#crumb").textContent="全部工具";
  $("#view").innerHTML=`
    <div class="card pad" style="margin-bottom:16px">
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <div><h1 style="font-size:1.28rem;margin-bottom:4px">🧰 密码工具箱</h1>
          <div class="muted tiny">${TOOLS.length} 个工具 · 全部本地计算 · 结果带步骤与说明</div></div>
        <div class="row"><a class="btn" href="#/docs">使用说明</a></div>
      </div>
    </div>
    ${GROUPS.map(g=>`<div style="margin-bottom:20px">
      <div class="row" style="justify-content:space-between;margin-bottom:9px">
        <h2>${ICON[g]||"•"} ${esc(g)}</h2>
        <span class="tiny muted">${TOOLS.filter(t=>t.group===g).length} 个</span>
      </div>
      <div class="tools">${TOOLS.filter(t=>t.group===g).map(t=>`
        <a class="tool" href="#/t/${t.id}" style="text-decoration:none;color:inherit">
          <b>${esc(t.name)}</b><span>${esc(t.desc)}</span></a>`).join("")}
      </div></div>`).join("")}
    <div id="histBox"></div>`;
  renderHist();
}

/* ---------- 工具页 ---------- */
function viewTool(id){
  const t=TOOLS.find(x=>x.id===id);
  if(!t){$("#view").innerHTML='<div class="empty"><div class="big">404</div>工具不存在</div>';return;}
  cur=t;curId=id;setNav(null);
  $("#crumb").innerHTML=`<a href="#/" style="color:var(--dim)">工具箱</a>
    <span class="muted" style="margin:0 6px">/</span>${esc(t.name)}`;
  $("#view").innerHTML=`
    <div class="card pad formcard">
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <div><h1 style="font-size:1.16rem;margin-bottom:2px">${esc(t.name)}</h1>
          <div class="muted tiny">${esc(t.group)} · ${esc(t.desc)}</div></div>
        ${t.example?`<button class="btn sm" id="bEx">填入示例</button>`:""}
      </div>
      <div id="FORM" style="margin-top:16px"></div>
      <div class="actions">
        <button class="btn primary" id="bRun">▶ 运行 <span class="tiny" style="opacity:.7">(Ctrl+Enter)</span></button>
        <button class="btn ghost" id="bClear">清空</button>
        <a class="btn ghost" href="#/">← 全部工具</a>
      </div>
      <div class="resbox" id="RESBOX"></div>
    </div>
    <div id="histBox" style="margin-top:18px"></div>`;
  renderForm(t);
  renderHist();
  const ex=$("#bEx");
  if(ex)ex.onclick=()=>{
    Object.entries(t.example||{}).forEach(([k,v])=>{
      const el=$(`[name="${k}"]`);if(!el)return;
      el.value=v;
    });
    toast("已填入示例");
  };
  $("#bRun").onclick=run;
  $("#bClear").onclick=()=>{$$("#FORM input,#FORM textarea").forEach(el=>{
    if(el.type==="checkbox")el.checked=false;else el.value="";});
    $("#RESBOX").innerHTML="";};
  const first=$("#FORM input,#FORM textarea,#FORM select");
  if(first)first.focus();
}

function renderForm(t){
  $("#FORM").innerHTML=t.fields.map(f=>{
    const id="f_"+f.name;
    if(f.type==="select"){
      return `<div class="field"><label for="${id}"><b>${esc(f.label)}</b>
        ${f.help?`<span>${esc(f.help)}</span>`:""}</label>
        <select id="${id}" name="${f.name}" class="sel">${(f.options||[]).map(o=>
          `<option value="${esc(o.v)}" ${String(o.v)===String(f.default)?"selected":""}>${esc(o.l)}</option>`
        ).join("")}</select></div>`;
    }
    if(f.type==="textarea"){
      return `<div class="field"><label for="${id}"><b>${esc(f.label)}</b>
        ${f.help?`<span>${esc(f.help)}</span>`:""}</label>
        <textarea id="${id}" name="${f.name}" rows="${f.rows||5}"
          placeholder="${esc(f.placeholder||"")}">${esc(f.default||"")}</textarea></div>`;
    }
    return `<div class="field"><label for="${id}"><b>${esc(f.label)}</b>
      ${f.help?`<span>${esc(f.help)}</span>`:""}</label>
      <input id="${id}" type="text" name="${f.name}" value="${esc(f.default||"")}"
        placeholder="${esc(f.placeholder||"")}"></div>`;
  }).join("");
}

function collect(){
  const o={};
  (cur.fields||[]).forEach(f=>{
    const el=$(`[name="${f.name}"]`);
    o[f.name]=el?el.value:"";
  });
  return o;
}

async function run(){
  if(!cur)return;
  const btn=$("#bRun");btn.disabled=true;
  const box=$("#RESBOX");
  box.innerHTML='<div class="resbox" style="margin-top:16px"><span class="spin"></span> 计算中…</div>';
  const t0=performance.now();
  try{
    const r=await apiPost("/api/tool/"+cur.id,collect());
    const ms=Math.round(performance.now()-t0);
    if(!r.ok){
      box.innerHTML=`<div class="hd"><span class="badge bad">✘ 失败</span>
        <span class="tiny muted">${ms} ms</span></div><div class="out">${esc(r.error||"未知错误")}</div>`;
      HIST.unshift({id:cur.id,name:cur.name,ok:false,out:r.error||"",ms,at:Date.now()});
    }else{
      box.innerHTML=`<div class="hd"><span class="badge ok">✔ 完成</span>
        <span class="tiny muted">${ms} ms</span>
        <button class="copy" id="cpRes">复制结果</button></div>
        <div class="out">${esc(r.result||"")}</div>
        ${(r.extras||[]).length?`<dl class="kvgrid">${r.extras.map(([k,v])=>
          `<dt>${esc(k)}</dt><dd>${esc(typeof v==="string"?v:JSON.stringify(v))}</dd>`).join("")}</dl>`:""}
        ${(r.steps||[]).length?`<details class="steps"><summary>步骤</summary>
          <ol>${r.steps.map(s=>`<li>${esc(s)}</li>`).join("")}</ol></details>`:""}`;
      const cp=$("#cpRes");if(cp)cp.onclick=()=>copyText(r.result||"");
      HIST.unshift({id:cur.id,name:cur.name,ok:true,out:r.result||"",ms,at:Date.now()});
      if(HIST.length>12)HIST.pop();
    }
    renderHist();
  }catch(e){
    box.innerHTML=`<div class="hd"><span class="badge bad">✘ 请求失败</span></div>
      <div class="out">${esc(e.message)}</div>`;
  }finally{btn.disabled=false;}
}

function renderHist(){
  const box=$("#histBox");if(!box)return;
  if(!HIST.length){box.innerHTML="";return;}
  box.innerHTML=`<div class="card"><div class="row" style="justify-content:space-between;margin-bottom:8px">
      <h2>本次会话记录</h2><button class="copy" id="cpHist">全部复制</button></div>
    <div class="hist">${HIST.map((h,i)=>`<div class="h" data-i="${i}">
      <span>${h.ok?'<span style="color:var(--ok)">✔</span>':'<span style="color:var(--err)">✘</span>'}</span>
      <b>${esc(h.name)}</b>
      <span class="mono" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        ${esc((h.out||"").split("\n")[0].slice(0,80))}</span>
      <span style="font-size:.72rem">${h.ms}ms</span></div>`).join("")}</div></div>`;
  $$("#histBox .h").forEach(el=>el.onclick=()=>{
    const h=HIST[+el.dataset.i];copyText(h.out||"");toast("已复制该条结果");
  });
  const b=$("#cpHist");if(b)b.onclick=()=>copyText(HIST.map(h=>
    `# ${h.name}\n${h.out}`).join("\n\n"));
}

/* ---------- 文档 ---------- */
function viewDocs(){
  curId=null;setNav("docs");$("#crumb").textContent="使用说明";
  $("#view").innerHTML=`
  <div class="card pad">${md(`
# 密码工具箱使用说明

所有计算都在本地服务进程内完成 (调用 lib/ctfk.py)，不联网、不留存输入。

## 基本操作

1. 左侧选择分组 → 点击工具卡片进入表单页。
2. 填写参数，点「运行」或按 Ctrl/⌘ + Enter。
3. 结果区展示主输出 + 附加信息 (验证/耗时/推导)，可一键复制。
4. 「填入示例」可快速体验；「清空」重置表单。

## 输入格式约定

- 大整数支持十进制、0x 十六进制、以及只含 0-9a-f 的十六进制串。
- 空白/逗号/分号分隔的整数会被解析为列表 (如 MT 输出、HNP 样本)。
- Hex 输入的字段会忽略空格与 0x 前缀。

## 工具速查

| 需求 | 工具 |
|---|---|
| 一串编码层层嵌套 | 自动剥壳 |
| 凯撒 / 维吉尼亚 / 仿射 / Playfair / Hill | 古典分组 |
| 单字节或重复密钥 XOR | XOR 分组 |
| 已知哈希求口令 (rockyou) | 字典破解哈希 |
| 已知 MAC 想追加内容 | MD5 长度扩展 |
| 要保持 CRC32 不变改内容 | CRC32 伪造 |
| RSA 各种经典攻击 | 数论/RSA 分组 (共模/广播/小指数/共享素数/Wiener/Fermat/Franklin/Coppersmith) |
| 光滑阶离散对数 | 离散对数 → BSGS / Pohlig |
| 预测随机数 | PRNG → MT19937 / LCG |
| 格攻击 | HNP / 背包 |

## 快捷键

- <kbd>/</kbd> 聚焦搜索 (工具列表页)
- <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 运行当前工具
- <kbd>Esc</kbd> 取消输入焦点

## 注意

- Coppersmith、单表替代破译、Pohlig-Hellman 属于重计算，可能需要数秒。
- 字典破解默认读 rockyou 前 20 万行，可在表单里调大 (受内存/时间限制)。
- 工具只做数学计算；flag 校验请在题目站 <a href="http://127.0.0.1:8787/" target="_blank">127.0.0.1:8787</a> 完成。
`)}</div>`;
}

/* ---------- 路由 ---------- */
function route(){
  const h=location.hash.replace(/^#/,"")||"/";
  if(h.startsWith("/t/")){viewTool(h.slice(3));}
  else if(h.startsWith("/docs")){viewDocs();}
  else{viewHome();}
  window.scrollTo({top:0});
}
window.addEventListener("hashchange",route);

document.addEventListener("keydown",e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==="Enter"){e.preventDefault();
    const b=$("#bRun");if(b)b.click();}
  if(e.key==="/"&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)){
    const q=$("#Q");if(q){e.preventDefault();q.focus();}}
});

async function boot(){
  try{
    const d=await apiGet("/api/tools");
    TOOLS=d.tools;GROUPS=d.groups;RES=d.resources||{};
  }catch(e){
    $("#view").innerHTML='<div class="empty"><div class="big">⚠</div>无法加载工具列表<br>'
      +'<span class="tiny">'+esc(e.message)+'</span></div>';return;
  }
  $("#gnav").innerHTML=GROUPS.map(g=>`<a href="#" data-g="${esc(g)}">
      <span class="ic">${ICON[g]||"•"}</span><span class="tx">${esc(g)}</span></a>`).join("");
  $$("#gnav a").forEach(a=>a.onclick=e=>{e.preventDefault();
    const g=a.dataset.g;const first=TOOLS.find(t=>t.group===g);
    if(first)location.hash="#/t/"+first.id;});
  $("#resline").innerHTML=`rockyou: ${RES.rockyou?'<span style="color:var(--ok)">✔ '+
    (RES.rockyou_lines?RES.rockyou_lines.toLocaleString()+" 行":"")+'</span>':
    '<span style="color:var(--err)">✘</span>'}<br>
    John: ${RES.john?'<span style="color:var(--ok)">✔</span>':'<span class="muted">—</span>'}
    · hashcat: ${RES.hashcat?'<span style="color:var(--ok)">✔</span>':'<span class="muted">—</span>'}`;
  route();
}
boot();
</script>
</body>
</html>
"""

PAGE = PAGE_RAW.replace("__CSS__", BASE_CSS).replace("__JS__", JS_HELPERS)


def serve(port=8788, quiet=False):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8788)
