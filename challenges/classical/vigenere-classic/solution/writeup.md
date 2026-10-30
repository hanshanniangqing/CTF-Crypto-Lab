# vigenere-classic — 题解

> classical / 简单 / 100 分 / 考点: 重合指数 (IC) 求密钥长度 + 卡方逐列破解

## 漏洞点
维吉尼亚密钥是周期性重复的: 同一密钥字母加密的所有位置相当于同一个凯撒
移位, 保留了英文的统计结构。密钥越短、密文越长, 泄露的统计信息越多。
重合指数 (IC) 能直接测量「分列后是否像英文」, 从而暴露密钥长度。

## 利用思路
1. 抽出密文字母序列, 对 L = 2..16 把密文分成 L 列, 计算每列的重合指数
   (英文约 0.067, 随机约 0.038), 平均 IC 最高的 L 即密钥长度。
2. 对每一列: 枚举 26 个移位, 用 ctfk.chi2_english 挑出卡方偏差最小的
   移位, 拼出完整密钥。
3. 用密钥解密全文 (ctfk.vigenere), 正则提取 flag{...}。

## 关键代码
L = max(range(2, 17), key=lambda L: mean_ic(ct[i::L] for i in range(L)))
key = ""
for i in range(L):
    col = ct[i::L]
    key += chr(97 + min(range(26), key=lambda sh:
        ctfk.chi2_english(caesar(col, -sh))))
plain = ctfk.vigenere(text, key, decrypt=True)

## 防御建议
- 密钥长度必须与消息长度相当 (一次一密), 否则周期性必然泄露。
- 避免跨消息重用密钥; 长文本会暴露每一列的统计特征。
- 现代方案应使用标准对称加密; 古典多表密码仅适合教学演示。
