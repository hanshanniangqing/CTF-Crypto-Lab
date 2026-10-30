# ntlm-crack — 题解

> cracking / 入门 / 100 分 / 考点: NTLM 哈希字典破解 (John the Ripper + rockyou)

## 漏洞点
本地账户使用弱口令，且 NTLM 哈希（MD4(UTF-16LE(password))，无盐）被转储。
无盐意味着同一口令的哈希全局相同——拿字典一跑就现形。这正是 ransomware
团伙拿到 secretsdump 输出后第一件事就是做的事。

## 利用思路
1. 从 ntlm_dump.txt 提取 6 条 (user, ntlm-hash)。
2. 首选 John the Ripper: john --format=NT --wordlist=rockyou --pot=临时pot。
3. 无 John 时纯 Python 枚举: NTLM = MD4(UTF-16LE(pw))，rockyou 每行的 MD4
   与目标比对（MD4 极快，百万级 < 1 分钟）。
4. Administrator 账户的口令即 flag body。

## 关键代码
h = MD4.new(); h.update(pw.encode("utf-16-le"))
if h.hexdigest().upper() == target: hit(pw)

## 防御建议
- 强制口令长度与复杂性策略 + 定期与泄露口令库比对（禁止 rockyou 类口令）。
- 启用 NTLMv2/LM 禁用，迁移 Kerberos；对高价值账户开启 Credential Guard。
- 域内部署 honey account，任何对其 NTLM 的使用立即告警。
