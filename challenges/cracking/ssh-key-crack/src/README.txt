离职运维留在跳板机上的加密 SSH 私钥 (传统 PEM, AES-128-CBC)。
口令来源: rockyou 第 73907 行。破解口令恢复私钥, 用它解密 challenge.txt:
challenge.txt = hex(RSA-OAEP 公钥加密的 flag)。
恢复私钥: openssl rsa -in id_rsa -passin pass:<口令> (或 john 破出后任意工具)。
