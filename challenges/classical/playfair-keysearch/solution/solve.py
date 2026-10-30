"""题解：playfair-keysearch
## 漏洞点
Playfair 的 5x5 方阵完全由密钥单词决定。如果密钥是词典里的常见词,
密钥空间就从 25! 骤缩到几万个词, 可以逐词构造方阵试解。同时英文消息
解密后的 bigram 分布远比错误方阵的乱码「像英文」, bigram 评分能直接
把正确密钥排到第一名。

## 利用思路
1. 读入 cipher.txt, 去掉排版空格得到密文字母串。
2. 遍历 lib/data/wordlist.txt 中的全部单词, 用每个词构造 Playfair 方阵
   解密整段密文 (ctfk.Playfair(w).decrypt)。
3. 用 ctfk.BigramModel 给每个候选明文评分, 按分数从高到低排序。
4. 依序检查候选明文: 消息自带分界句式 "the hidden message begins flag
   ... the rest follows", 取 "flag" 与 "therest" 之间的字母即 flag 正文;
   找到后输出 flag{正文}。

## 关键代码
for w in words:
    dec = ctfk.Playfair(w).decrypt(ct)
    cands.append((model.score(dec.lower()), dec))
cands.sort(key=lambda t: -t[0])            # 正确密钥评分最高
i = dec.find("flag"); j = dec.find("therest", i)
print("flag{" + dec[i+4:j] + "}")

## 防御建议
- 密钥绝不能使用词典词: 可枚举的密钥空间等于没有密钥。
- 应使用足够长的随机密钥流 (等效随机 5x5 方阵) 而非人易记的口令。
- Playfair 只混淆字母对、不隐藏长度与位置信息, 现代场景请用标准算法。
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def extract_flag(dec):
    """消息自带分界句式: '... begins flag XXX the rest follows ...'"""
    d = dec.lower()
    i = d.find("flag")
    if i < 0:
        return None
    j = d.find("therest", i + 4)
    if j > 0 and d[i + 4:j]:
        return "flag{" + d[i + 4:j] + "}"
    m = re.search(r"flag([a-z]+)", d)
    return "flag{" + m.group(1) + "}" if m else None


def main():
    ct = "".join(open("cipher.txt", encoding="utf-8").read().split()).upper()
    words = (ROOT / "lib" / "data" / "wordlist.txt").read_text(encoding="utf-8").split()
    model = ctfk.BigramModel()
    cands = []
    for w in words:
        try:
            dec = ctfk.Playfair(w).decrypt(ct)
        except Exception:
            continue
        cands.append((model.score(dec.lower()), dec))
    cands.sort(key=lambda t: -t[0])
    for _, dec in cands:
        f = extract_flag(dec)
        if f:
            print(f)
            return
    raise SystemExit("词表爆破未能恢复 flag")


if __name__ == "__main__":
    main()
