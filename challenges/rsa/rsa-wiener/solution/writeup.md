# rsa-wiener — 题解

> rsa / 中等 / 250 分 / 考点: Wiener 攻击 (小私钥指数, 连分数)

## 漏洞点
为追求解密速度，私钥指数 d 被选得极小（约 130 bit，远小于
n^(1/4)/3）。Wiener 证明：此时 e·d - 1 = k·phi 中 k/d 是 e/n 的
连分数渐近分数，因此对 e/n 做连分数展开、逐项代入
x² - (n-phi+1)x + n = 0 检验，即可精确恢复 d。

## 利用思路
1. 读附件中的 n, e, c。
2. 用 ctfk.wiener(e, n) 对 e/n 做连分数攻击，直接返回 d。
3. m = c^d mod n，转回字节即得 flag。

## 关键代码
d = ctfk.wiener(e, n)        # 连分数渐近分数里的 k/d
assert d is not None
print(long_to_bytes(pow(c, d, n)).decode())

## 防御建议
- 私钥指数 d 不得人为取小；标准做法是先选 e（如 65537）再导出 d。
- 若必须用小 d，应采用 Wiener 结界之外的方案（如 RFC 8017 建议的
  d > n^0.25，或加随机盲化），并配合侧信道防护。
- 密钥审计：检查 d 与 n^(1/4) 的比值。
