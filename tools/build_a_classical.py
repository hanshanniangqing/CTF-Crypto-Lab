# -*- coding: utf-8 -*-
"""classical 分类出题脚本 (共 7 题): base-nested, caesar-rot, vigenere-classic,
substitution-hillclimb, affine-brute, playfair-keysearch, hill-knownpt

通用做法: 英文语料取自 lib/data/corpus_en.txt 的固定偏移 (保证确定性),
含 flag 的句子插入文本中段融入语料。所有随机性均来自 rng_for(题目名)。
每题自检中都会用「与 solve.py 相同的攻击逻辑」反推一遍答案, 确保材料 100% 可解。
"""
import base64
import math
import random
import re

from build_common import *

CORPUS = (LAB / "lib" / "data" / "corpus_en.txt").read_text(encoding="utf-8")
LETTERS = "".join(c for c in CORPUS if "a" <= c <= "z")
ALPHA = "abcdefghijklmnopqrstuvwxyz"
WORDLIST = (LAB / "lib" / "data" / "wordlist.txt").read_text(encoding="utf-8").split()


def corpus_slice(start, n):
    seg = CORPUS[start:start + n]
    assert len(seg) == n, f"corpus 切片 {start}:{start + n} 越界"
    return seg


def insert_sentence(text, sentence):
    """把句子插到文本中段的空格处, 使其按语料风格融入"""
    mid = len(text) // 2
    pos = text.find(" ", mid)
    if pos < 0:
        pos = text.rfind(" ", 0, mid)
    return text[:pos] + " " + sentence + text[pos:]


def det3(M):
    return (M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
            - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0]))


# ====================================================================
# 1. base-nested — 嵌套编码 (hex/base32/base64/ascii85 随机 5~7 层)
# ====================================================================
ENC = {
    "hex": lambda b: b.hex().encode(),
    "base32": base64.b32encode,
    "base64": base64.b64encode,
    "ascii85": base64.a85encode,
}
DEC = {
    "hex": lambda b: bytes.fromhex(b.decode("ascii")),
    "base32": base64.b32decode,
    "base64": base64.b64decode,
    "ascii85": base64.a85decode,
}


@register("base-nested")
def gen_base_nested(ch):
    flag = ch["flag"]
    rng = rng_for("base-nested")
    pool = ["hex", "base32", "base64", "ascii85"]
    seq = data = None
    for _ in range(300):
        n_layers = rng.randint(5, 7)
        s = [rng.choice(pool) for _ in range(n_layers)]
        cur = flag.encode()
        for name in s:                      # 从内向外逐层编码
            cur = ENC[name](cur)
        # 附件必须能被 ctfk.try_decode_layers 干净剥开 (题目的提示依赖它)
        got, names = ctfk.try_decode_layers(cur)
        if got == flag.encode() and names == s[::-1]:
            seq, data = s, cur
            break
    assert seq is not None, "base-nested: 300 次内未生成可干净剥壳的材料"
    write_src("base-nested", "encoded.txt", data.decode("ascii") + "\n")
    # 自检 1: 按层序反向手写解码还原 flag
    cur = data
    for name in reversed(seq):
        cur = DEC[name](cur)
    verify("base-nested", cur == flag.encode(), "逐层反向解码未还原 flag")
    verify("base-nested", flag in cur.decode(), "最内层文本缺少 flag")
    # 自检 2: 工具箱自动剥壳结果与编码层序一致
    verify("base-nested", ctfk.try_decode_layers(data) == (flag.encode(), seq[::-1]),
           "ctfk.try_decode_layers 无法按层序剥开附件")


# ====================================================================
# 2. caesar-rot — 凯撒移位 + 卡方评分
# ====================================================================
@register("caesar-rot")
def gen_caesar_rot(ch):
    flag = ch["flag"]
    rng = rng_for("caesar-rot")
    sentence = ("The secret code is flag{caesar_was_not_so_smart} "
                "and it must stay hidden.")
    plain = insert_sentence(corpus_slice(4000, 460), sentence)
    shift = rng.randint(1, 25)
    cipher = ctfk.caesar_shift(plain, shift)
    write_src("caesar-rot", "cipher.txt", cipher + "\n")
    back = ctfk.caesar_shift(cipher, -shift)
    verify("caesar-rot", back == plain, "凯撒解密未还原明文")
    verify("caesar-rot", flag in back, "还原明文中缺少 flag")
    # 自检 3: 与 solve 相同的攻击 (26 移位逐一卡方评分) 能找回正确移位
    best = min(range(26),
               key=lambda k: ctfk.chi2_english(ctfk.caesar_shift(cipher, -k)))
    verify("caesar-rot", best == shift, f"卡方评分选错移位 ({best} != {shift})")


# ====================================================================
# 3. vigenere-classic — IC 求密钥长度 + 逐列卡方
# ====================================================================
def _ic(col):
    n = len(col)
    if n < 2:
        return 0.0
    cnt = {}
    for c in col:
        cnt[c] = cnt.get(c, 0) + 1
    return sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1))


def vigenere_key_lengths(cipher):
    """按平均重合指数从高到低返回候选密钥长度 2..16"""
    s = "".join(c for c in cipher.lower() if c.isalpha())
    scored = []
    for L in range(2, 17):
        cols = [s[i::L] for i in range(L)]
        scored.append((sum(_ic(c) for c in cols) / L, L))
    scored.sort(reverse=True)
    return [L for _, L in scored]


def vigenere_recover_key(cipher, L):
    """逐列卡方还原长度为 L 的密钥"""
    s = "".join(c for c in cipher.lower() if c.isalpha())
    key = ""
    for i in range(L):
        col = s[i::L]
        best = min(range(26), key=lambda sh: ctfk.chi2_english(
            "".join(chr((ord(c) - 97 - sh) % 26 + 97) for c in col)))
        key += chr(97 + best)
    return key


@register("vigenere-classic")
def gen_vigenere_classic(ch):
    flag = ch["flag"]
    rng = rng_for("vigenere-classic")
    sentence = ("the passphrase of this letter was settled long ago and "
                "flag{vigenere_cracked_by_ic} is woven into the middle of it.")
    plain = insert_sentence(corpus_slice(9000, 780), sentence)
    key = "".join(rng.choice(ALPHA) for _ in range(6))
    cipher = ctfk.vigenere(plain, key)
    write_src("vigenere-classic", "cipher.txt", cipher + "\n")
    dec = ctfk.vigenere(cipher, key, decrypt=True)
    verify("vigenere-classic", dec == plain, "维吉尼亚解密未还原明文")
    verify("vigenere-classic", flag in dec, "还原明文中缺少 flag")
    # 自检 3: 与 solve 相同的攻击 (IC 选长 + 逐列卡方) 能还原密钥
    rec = vigenere_recover_key(cipher, vigenere_key_lengths(cipher)[0])
    verify("vigenere-classic", rec == key, f"IC+卡方攻击还原密钥失败 ({rec} != {key})")


# ====================================================================
# 4. substitution-hillclimb — 单表替代 + bigram 爬山
# ====================================================================
def hillclimb_decrypt(cipher, restarts=8, attempts=1500, seed=12345):
    """bigram 爬山破解单表替代 (与 solution/solve.py 内实现保持一致):
    固定 seed 随机初始映射, 每轮随机交换两个字母的映射, 整轮无改进则重启,
    取历史最优映射解密全文。"""
    rng = random.Random(seed)
    model = ctfk.BigramModel()
    lp, floor = model.logp, model.floor
    low = cipher.lower()
    n = len(low)

    def score(perm):
        s = low.translate(str.maketrans(ALPHA, "".join(perm)))
        get = lp.get
        return sum(get(s[i:i + 2], floor) for i in range(n - 1)) / max(1, n - 1)

    best_perm, best_sc = None, -1e30
    for _ in range(restarts):
        perm = list(ALPHA)
        rng.shuffle(perm)
        cur = score(perm)
        while True:
            improved = False
            for _ in range(attempts):
                i, j = rng.randrange(26), rng.randrange(26)
                if i == j:
                    continue
                perm[i], perm[j] = perm[j], perm[i]
                s2 = score(perm)
                if s2 > cur:
                    cur, improved = s2, True
                else:
                    perm[i], perm[j] = perm[j], perm[i]
            if not improved:
                break
        if cur > best_sc:
            best_sc, best_perm = cur, perm[:]
    return low.translate(str.maketrans(ALPHA, "".join(best_perm)))


@register("substitution-hillclimb")
def gen_substitution_hillclimb(ch):
    flag = ch["flag"]
    rng = rng_for("substitution-hillclimb")
    sentence = ("every letter in this note was swapped by a fixed secret table "
                "and flag{substitution_down_you_go} is the only trace left behind.")
    plain = insert_sentence(corpus_slice(16000, 720), sentence)
    perm = list(ALPHA)
    rng.shuffle(perm)                       # enc: alpha[i] -> perm[i]
    enc = str.maketrans(ALPHA, "".join(perm))
    dec = str.maketrans("".join(perm), ALPHA)
    cipher = plain.translate(enc)
    write_src("substitution-hillclimb", "cipher.txt", cipher + "\n")
    verify("substitution-hillclimb", cipher.translate(dec) == plain, "映射表解密未还原明文")
    verify("substitution-hillclimb", sorted(perm) == list(ALPHA), "替代映射不是双射")
    # 自检 3: 与 solve 相同的爬山攻击 (固定 seed) 能恢复明文
    verify("substitution-hillclimb", flag in hillclimb_decrypt(cipher),
           "bigram 爬山未能恢复明文")


# ====================================================================
# 5. affine-brute — 仿射密码 312 密钥爆破
# ====================================================================
def affine_encrypt(text, a, b):
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((a * (ord(c) - 97) + b) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((a * (ord(c) - 65) + b) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


@register("affine-brute")
def gen_affine_brute(ch):
    flag = ch["flag"]
    rng = rng_for("affine-brute")
    sentence = ("the scholar laughed at the idea because "
                "flag{affine_312_ways_to_fail} was protected by nothing but arithmetic.")
    plain = insert_sentence(corpus_slice(23000, 470), sentence)
    a = rng.choice([5, 7, 11, 15, 17, 19, 21, 23, 25])
    b = rng.randint(0, 25)
    cipher = affine_encrypt(plain, a, b)
    write_src("affine-brute", "cipher.txt", cipher + "\n")
    dec = ctfk.affine_decrypt(cipher, a, b)
    verify("affine-brute", dec == plain, "仿射解密未还原明文")
    verify("affine-brute", flag in dec, "还原明文中缺少 flag")
    # 自检 3: 与 solve 相同的 312 密钥爆破能命中真实密钥
    best = min((ctfk.chi2_english(ctfk.affine_decrypt(cipher, aa, bb)), aa, bb)
               for aa in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
               for bb in range(26))
    verify("affine-brute", (best[1], best[2]) == (a, b),
           f"爆破未命中真实密钥 (得到 {best[1]},{best[2]}, 期望 {a},{b})")


# ====================================================================
# 6. playfair-keysearch — Playfair + 词表密钥爆破
# ====================================================================
def playfair_extract(dec):
    """从 (小写化前的) 解密文本提取 flag; 消息自带分界词 'the rest follows'"""
    d = dec.lower()
    i = d.find("flag")
    if i < 0:
        return None
    j = d.find("therest", i + 4)
    if j > 0 and d[i + 4:j]:
        return "flag{" + d[i + 4:j] + "}"
    m = re.search(r"flag([a-z]+)", d)
    return "flag{" + m.group(1) + "}" if m else None


def playfair_keysearch_attack(cipher):
    """词表爆破: 每个词构造方阵解密, bigram 评分排序, 返回首个可提取 flag 的解密文本"""
    ct = "".join(cipher.split()).upper()
    model = ctfk.BigramModel()
    cands = []
    for w in WORDLIST:
        try:
            dec = ctfk.Playfair(w).decrypt(ct)
        except Exception:
            continue
        cands.append((model.score(dec.lower()), dec))
    cands.sort(key=lambda t: -t[0])
    for _, dec in cands:
        if playfair_extract(dec):
            return dec
    return cands[0][1] if cands else None


@register("playfair-keysearch")
def gen_playfair_keysearch(ch):
    flag = ch["flag"]
    rng = rng_for("playfair-keysearch")
    cand = [w for w in WORDLIST if 6 <= len(w) <= 9]
    key = cand[rng.randrange(len(cand))]
    # 明文以偶数长的前缀开头, 保证 flag 片段内部不产生 X 填充干扰
    plain = ("the hidden message begins flag playfairsquarehunt the rest follows "
             + LETTERS[25000:25000 + 300])
    assert len("".join(c for c in plain if c.isalpha())) >= 300
    pf = ctfk.Playfair(key)
    cipher = pf.encrypt(plain)
    grouped = " ".join(cipher[i:i + 5] for i in range(0, len(cipher), 5))
    write_src("playfair-keysearch", "cipher.txt", grouped + "\n")
    d = pf.decrypt(cipher)
    verify("playfair-keysearch", "flagplayfairsquarehunt" in d.lower(), "同 key 解密缺少 flag 片段")
    verify("playfair-keysearch", key in cand and 6 <= len(key) <= 9, "密钥必须来自词表 6~9 词")
    # 自检 3: 与 solve 相同的词表爆破能恢复 flag
    found = playfair_keysearch_attack(cipher)
    verify("playfair-keysearch", found is not None and playfair_extract(found) == flag,
           "词表爆破未能恢复 flag")


# ====================================================================
# 7. hill-knownpt — Hill 密码已知明文攻击 (模 26 线性方程组)
# ====================================================================
def blocks_to_text(vectors):
    return "".join(chr(97 + v) for row in vectors for v in row)


@register("hill-knownpt")
def gen_hill_knownpt(ch):
    flag = ch["flag"]
    rng = rng_for("hill-knownpt")
    # 1) 随机密钥矩阵 K: det 必须与 26 互素, 否则重摇
    while True:
        K = [[rng.randrange(26) for _ in range(3)] for _ in range(3)]
        if math.gcd(det3(K), 26) == 1:
            break
    # 2) 已知明文取语料 12 个字母 (4 块 x 3 字母), 前 3 块组成的矩阵要可逆 mod 26
    start = rng.randrange(0, 40000)
    for off in range(start, start + 2000):
        blocks = [LETTERS[off + 3 * i: off + 3 * i + 3] for i in range(4)]
        M = [[ord(c) - 97 for c in blk] for blk in blocks[:3]]
        if math.gcd(det3(M), 26) == 1:
            break
    else:
        raise AssertionError("hill-knownpt: 未找到可逆的已知明文块")
    pt = [[ord(c) - 97 for c in blk] for blk in blocks]
    ct = ctfk.mat_mul_mod(pt, K, 26)
    # 3) flag 明文 pad 到 3 的倍数 (27 字母 = 9 块) 后加密
    fpt_text = "flaghillcipherlinearizedxxx"
    fpt = [[ord(c) - 97 for c in fpt_text[i:i + 3]] for i in range(0, len(fpt_text), 3)]
    fct = ctfk.mat_mul_mod(fpt, K, 26)

    lines = [
        "Hill cipher, 3x3 key matrix over Z_26 (a=0 ... z=25).",
        "Encryption: ct_block = pt_block * K (mod 26); each block is 3 letters.",
        "",
        "Known plaintext / ciphertext pairs (4 blocks):",
        "",
    ]
    for pb, cb in zip(pt, ct):
        p = "".join(chr(97 + v) for v in pb)
        c = "".join(chr(97 + v) for v in cb)
        lines.append(f"pt={p} ct={c}")
    lines += [
        "",
        "Ciphertext whose plaintext contains the flag (9 blocks):",
        "",
        "ct=" + " ".join("".join(chr(97 + v) for v in row) for row in fct),
    ]
    write_src("hill-knownpt", "hill.txt", "\n".join(lines) + "\n")

    # 自检 1: 已知明文对恢复 K (用 ctfk.hill_key_from_knownpt)
    rec = ctfk.hill_key_from_knownpt(pt[:3], ct[:3])
    verify("hill-knownpt", rec == K, "hill_key_from_knownpt 未恢复 K")
    # 自检 2: 重加密 4 块已知明文 == 4 块已知密文
    verify("hill-knownpt", ctfk.mat_mul_mod(pt, K, 26) == ct, "K 重加密已知明文不匹配")
    # 自检 3: 用 ct 为 "明文" 反解 K^-1, 解密 flag 密文还原 flag 明文
    Kinv = ctfk.hill_key_from_knownpt(ct[:3], pt[:3])
    back = blocks_to_text(ctfk.mat_mul_mod(fct, Kinv, 26))
    verify("hill-knownpt", back == fpt_text, "Kinv 解密 flag 密文未还原明文")
    verify("hill-knownpt", flag == "flag{" + back[4:-3].rstrip("x") + "}",
           "flag 明文段与 index 中的 flag 不一致")


if __name__ == "__main__":
    run_builders(BUILDERS)
