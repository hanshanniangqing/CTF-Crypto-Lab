# rsa-coppersmith — 题解

> rsa / 困难 / 400 分 / 考点: Coppersmith 已知 p 高位分解

## 漏洞点
侧信道泄露了素数 p 的高 112 位（p_high = p >> 48，低 48 位未知）。
Coppersmith 方法（Howgrave-Graham + LLL）可以求多项式 f(x) =
p_high·2^48 + x 在模 n 下小于 n^0.25 的根：只要未知量 x0 < 2^48
远小于该界，格约简就能把 f(x0) = p 「顶」出来，从而完整分解 n。

## 利用思路
1. 读附件中的 n, e, c, p_high。
2. 构造首一多项式 f(x) = (p_high << 48) + x，未知低 48 位为 x0。
3. 调 ctfk.small_roots(f, n, beta=0.5, X=2^48, m=3, t=3) 求根。
4. 由根重构 p = (p_high << 48) + x0（校验 n % p == 0），q = n // p。
5. d = e^-1 mod (p-1)(q-1)，m = c^d mod n，转回字节即得 flag。

## 关键代码
roots = ctfk.small_roots([p_high << 48, 1], n, 0.5, 1 << 48, m=3, t=3)
p = next((p_high << 48) + r for r in roots if r >= 0 and n % ((p_high << 48) + r) == 0)
d = ctfk.modinv(e, (p - 1) * (n // p - 1))

## 防御建议
- 私钥的任何比特（哪怕高位）都不得通过侧信道、日志、核心转储泄露。
- 侧信道防护：恒定时间实现、掩码、禁用交换文件/内存转储中的密钥页。
- 密钥材料零化：使用后清零内存，避免长期驻留可被读取的存储。
