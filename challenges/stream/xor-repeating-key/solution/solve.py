"""题解：xor-repeating-key
## 漏洞点
重复密钥 XOR 相当于把密钥周期性地叠在明文上: 位置相差密钥长度整数倍的
字节全部用同一个密钥字节加密。密钥只有 7 字节, 而明文是上千字符的英文,
两条统计规律立刻出卖它——(1) 英文文本间的按位汉明距离明显低于随机数据,
可用来猜密钥长度; (2) 同一列内的单字节 XOR 可用字符频率分析逐列破开。

## 利用思路
1. 对每个候选密钥长度 k (2..40), 取多组相邻 k 字节块, 计算归一化汉明
   距离 hamming(b1,b2)/k, 平均后按距离升序排列 (正确长度与它的倍数都低)。
2. 依序尝试候选 k: 把密文按位置 j mod k 分列, 每列对 256 个候选密钥字节
   解密并用「英文可见字符加权评分」打分, 取最高者为该列密钥字节。
   (评分区分大小写并对不可打印字符重罚, 避免大小写翻转的平分陷阱。)
3. 组合各列密钥字节解密全文, 用正则提取 flag{...};
   本题 7 是 14/21/35 的因子, 因此这些倍数长度同样能解出全文。

## 关键代码
for k in keylen_order(ct):
    key = bytes(max(range(256), key=lambda g, col=ct[j::k]:
                printable_score(xor(col, bytes([g])))) for j in range(k))
    text = xor(ct, key)
    m = re.search(r"flag\\{[^}\\s]*\\}", text)

## 防御建议
- 重复密钥 XOR 只能当混淆, 绝不能当加密; 流加密请用 nonce+ChaCha20/AES-CTR。
- 若必须 XOR, 密钥长度应不小于消息长度 (真一次性密码本) 且密钥来自 CSPRNG。
- 避免让高可预测性的结构化文本 (日志、模板) 直接暴露在同一密钥下。
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk

_PUNCT = ".,'\";:!?-()"


def printable_score(text):
    """英文可见字符加权评分, 越大越像英文; 区分大小写, 罚不可打印字符"""
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


def keylen_order(ct):
    """归一化汉明距离估密钥长度, 距离小者在前"""
    scores = {}
    for k in range(2, 41):
        n = min(8, len(ct) // k - 1)
        if n < 2:
            continue
        tot = 0.0
        for b in range(n):
            tot += ctfk.hamming_bits(ct[b * k:(b + 1) * k],
                                     ct[(b + 1) * k:(b + 2) * k]) / k
        scores[k] = tot / n
    return sorted(scores, key=lambda k: scores[k])


def main():
    hexdata = "".join(
        line for line in open("ciphertext.txt", encoding="utf-8").read().split("\n")
        if line.strip() and not line.strip().startswith("#"))
    ct = bytes.fromhex("".join(hexdata.split()))
    order = keylen_order(ct)
    for k in order:
        key = bytes(max(range(256),
                        key=lambda g, col=ct[j::k]:
                        printable_score(
                            ctfk.xor_bytes(col, bytes([g])).decode("latin-1")))
                    for j in range(k))
        text = ctfk.xor_bytes(ct, key).decode("latin-1")
        m = re.search(r"flag\{[^}\s]*\}", text)
        if m:
            print(m.group(0))
            return
    raise SystemExit("key not recovered")


main()
