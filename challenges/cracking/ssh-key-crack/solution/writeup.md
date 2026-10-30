# ssh-key-crack — 题解

> cracking / 中等 / 250 分 / 考点: 加密 SSH 私钥破解 (ssh2john + john)

## 漏洞点
私钥文件使用传统 PEM 加密 (Proc-Type: 4,ENCRYPTED)。这类格式的口令 KDF
只做了极少的拉伸，口令验证速率极高——John the Ripper 配合 rockyou 字典
几分钟内就能穷举千万级弱口令。私钥一旦泄露，其保护的一切凭据随之失守。

## 利用思路
1. ssh2john.py id_rsa > hash.txt (john jumbo 自带该转换脚本)。
2. john --wordlist=rockyou hash.txt 爆破口令 (本题口令在 rockyou 前 10 万行)。
3. openssl rsa -in id_rsa -passin pass:<口令> 解出明文私钥。
4. RSA.import_key 导入私钥, RSA-OAEP 解密 challenge.txt (hex) 得 flag。

## 关键代码
subprocess.run(["openssl", "rsa", "-in", "id_rsa", "-passin", "pass:" + pw,
                "-out", "plain.pem"])
priv = RSA.import_key(open("plain.pem").read())
flag = PKCS1_OAEP.new(priv).decrypt(bytes.fromhex(open("challenge.txt").read()))

## 防御建议
- 生成密钥用 OpenSSH 新格式 (bcrypt KDF, aes256-ctr), 口令高强度不重用。
- 私钥不落盘共享目录; 用 ssh-agent 与证书 (SSH CA) 替代长期私钥分发。
- 对跳板机 authorized_keys 加 from=/expiry-time 限制, 私钥泄露立即吊销。
