一次失误的备份把 /etc/shadow 带了出来 (sha512crypt, $6$)。
3 个可登录账户的口令都来自常见字典。破解 deploy 的口令后解密 vault.txt:
flag = xor(vault_hex, sha256('vault:' + deploy口令)) 逐字节异或。
