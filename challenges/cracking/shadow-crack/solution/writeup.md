# shadow-crack — 题解

> cracking / 中等 / 300 分 / 考点: sha512crypt 口令破解 (unshadow 场景, $6$)

## 漏洞点
/etc/shadow 里的 $6$ (sha512crypt) 虽是慢哈希 (默认 5000 轮)，但口令本身来自
常见字典——慢哈希防不住弱口令，只是把穷举时间乘上 5000。John the Ripper 的
高度优化实现 (SIMD + 多线程) 依然能在分钟级吃掉千万级字典。

## 利用思路
1. (可选) unshadow passwd.txt shadow.txt 合并成 john 输入格式。
2. john --wordlist=rockyou shadow.txt —— john 自动识别 $6$ 并并行破解。
3. john --show 读回全部口令；deploy 的口令用于解密 vault.txt：
   flag = xor(hex→bytes, sha256("vault:" + deploy口令)) 逐字节异或。
4. 本题纯 Python 不可行 (sha512crypt 单条 ~25ms)，需要 John (或 hashcat)。

## 关键代码
import hashlib
ks = hashlib.sha256(b"vault:" + deploy_pw).digest() * 2
flag = bytes(a ^ b for a, b in zip(bytes.fromhex(vault_hex), ks))

## 防御建议
- /etc/shadow 权限 000，备份系统排除敏感文件并加密存储。
- 口令策略: 长度 ≥ 12 且与泄露字典比对; 高权限账户强制 MFA。
- 部署 fail2ban/auditd, 对 su/sudo 失败峰值告警; 定期用 john 自查口令强度。
