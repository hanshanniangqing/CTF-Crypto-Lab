"""题解：substitution-hillclimb
## 漏洞点
单表替代密码对每个字母做固定替换, 明文的字母频率、连字 (bigram) 分布
原封不动地映射到密文上。英文的 bigram (如 th/he/in) 分布极不均匀, 密文
足够长时, 任何错误映射都会让解密结果的 bigram 评分显著变差, 于是可以
把「破解」变成一个可爬山的优化问题。

## 利用思路
1. 用英文语料构建 bigram 对数概率模型 (ctfk.BigramModel)。
2. 随机生成初始映射 (固定 seed 保证可复现), 计算当前解密文本的评分。
3. 每轮随机交换两个字母的映射: 评分提高则保留, 否则撤销; 一整轮
   (1500 次尝试) 都无改进视为收敛, 随机重启进入下一轮 (共 8 次重启)。
4. 记录历史最优映射, 用它解密全文, 正则提取 flag{...}。

## 关键代码
perm = list(ALPHA); rng.shuffle(perm)          # 随机初始映射
for _ in range(attempts):                      # 每轮 1500 次交换尝试
    i, j = rng.randrange(26), rng.randrange(26)
    perm[i], perm[j] = perm[j], perm[i]
    s2 = score(perm)                           # bigram 对数概率
    if s2 > cur: cur, improved = s2, True
    else: perm[i], perm[j] = perm[j], perm[i]

## 防御建议
- 单表替代不改变任何统计结构, 长文本必然被频率/连字分析破解。
- 加长密钥并不能修复统计泄露, 需要改变「明文统计形状」的方案 (如流密码)。
- 现代场景使用 AES/ChaCha20; 短消息也应加入随机填充避免固定模式。
"""
import pathlib
import random
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk

ALPHA = "abcdefghijklmnopqrstuvwxyz"


def hillclimb_decrypt(cipher, restarts=8, attempts=1500, seed=12345):
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


def main():
    cipher = open("cipher.txt", encoding="utf-8").read()
    plain = hillclimb_decrypt(cipher)
    m = re.search(r"flag\{[^}]*\}", plain)
    assert m, "爬山恢复的明文中未找到 flag"
    print(m.group(0))


if __name__ == "__main__":
    main()
