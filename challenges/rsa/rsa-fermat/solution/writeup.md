# rsa-fermat — 题解

> rsa / 中等 / 200 分 / 考点: Fermat 分解 (相近素数)

## 漏洞点
素数 p、q 由同一随机源在附近取值生成（q 紧跟在 p+gap 之后），两者
非常接近。Fermat 分解法正是利用这一点：n = a² - b²，其中
a = (p+q)/2、b = (q-p)/2。当 q-p 相对 √n 很小时，从 ⌈√n⌉ 向上枚举
a，很快就能让 a²-n 成为完全平方数，从而恢复 p、q。

## 利用思路
1. 读附件中的 n, e, c。
2. 用 ctfk.fermat_factor(n) 得到 (p, q)。
3. phi = (p-1)(q-1)，d = e^-1 mod phi。
4. m = c^d mod n，转回字节即得 flag。

## 关键代码
p, q = ctfk.fermat_factor(n)   # 从 ceil(sqrt(n)) 起找 a²-n = 完全平方
d = ctfk.modinv(e, (p - 1) * (q - 1))
print(long_to_bytes(pow(c, d, n)).decode())

## 防御建议
- 素数必须独立、均匀地随机生成；生成后检查 |p-q| 是否过大（接近）。
- 常规做法：分别独立生成两个固定长度的随机素数即可，不要人为联动。
- 密钥审计时可用 Fermat 法批量筛查相近素数模数。
