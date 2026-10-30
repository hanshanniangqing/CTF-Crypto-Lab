# zip-crack — 题解

> cracking / 简单 / 150 分 / 考点: ZipCrypto 传统加密压缩包破解 (zip2john + john)

## 漏洞点
传统 ZipCrypto (PKZIP 流加密) 有两大死穴：口令可以离线穷举；其 12 字节加密头
的最后一个字节是 CRC 校验字节，speedup 后字典验证只需极小代价。弱口令 +
ZipCrypto = 等同明文存储。

## 利用思路
1. zip2john.exe leaked.zip 提取 john 格式哈希。
2. john --wordlist=rockyou 跑字典 (ZipCrypto 极快，分钟内覆盖千万级词表)。
3. john --show 读回口令；Python zipfile(zip, pwd=口令) 读出 flag.txt。
4. 无 John 时退化为 zipfile + rockyou 逐条尝试 (每条 ~0.1ms)。

## 关键代码
z = zipfile.ZipFile("leaked.zip")
data = z.read("flag.txt", pwd=pw.encode())   # 口令错则抛 RuntimeError

## 防御建议
- 禁用 ZipCrypto；确需压缩加密时使用 AES-256 (7-Zip/WinRAR AES)。
- 归档口令不允许出现在历史泄露字典中，走密码管理器生成。
- 邮件网关/EDR 对带密码压缩包的投递链路做标记与告警。
