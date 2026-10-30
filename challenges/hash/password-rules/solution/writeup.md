# password-rules — 题解

> hash / 简单 / 100 分 / 考点: 字典攻击 + 规则变形 (hashcat 思路)

## 漏洞点
五个 MD5 口令哈希（无盐），口令都是"词典单词 + 简单规则变形"：首字母大写、
尾部追加年份、加 !、常见 leet 替换 (a→@, e→3, i→1, o→0, s→$, t→7)。
这类口令的搜索空间是 词表 × 规则 的笛卡尔积——hashcat 的规则攻击
(-r best64.rule) 正是为此设计。MD5 计算极快又无盐，全部哈希必然沦陷。

## 利用思路
1. 读 hashes.txt 得 5 个 md5 → 用户名映射（user5 是 admin）。
2. 读词表 wordlist.txt（附件内附，即项目 lib/data/wordlist.txt 的副本）。
3. 对每个词生成候选：原词 / 首字母大写 / +! / leet 变形 /
   原词+年份(1900..2030) / leet+年份，逐一 md5 与目标比对。
4. 全部命中后，取 admin 条目恢复出的口令 pw，输出 flag{pw}。

## 关键代码
for w in words:
    for cand in (w, w.capitalize(), w + "!", leet(w)):
        try_pw(cand)
    for y in range(1900, 2031):
        try_pw(w + str(y)); try_pw(leet(w) + str(y))
admin_pw = found[admin_hash]
print("flag{" + admin_pw + "}")

## 防御建议
- 口令哈希必须加盐并使用慢函数（bcrypt / scrypt / Argon2），抬高离线爆破成本。
- 口令策略应对照泄露库 (HIBP) 检查，而不是强制"大写+数字+符号"这类可预测变形。
- 词典词 + 规则变形的组合在规则攻击面前等同明文；用足够长的随机 passphrase。
