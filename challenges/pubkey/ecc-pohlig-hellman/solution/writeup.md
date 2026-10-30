# ecc-pohlig-hellman — 题解

> pubkey / 困难 / 350 分 / 考点: 椭圆曲线光滑阶离散对数 (超奇异曲线)

## 漏洞点
曲线 y² = x³ + 1 在 p ≡ 2 (mod 3) 时是超奇异曲线，#E(F_p) = p+1 可由 p 直接
算出。出题人反着构造参数：先凑一个全由小因子组成的光滑 M（本题为
12 × 若干 12~14 bit 素数，最大因子 ≤ 2^14），再取 p = M-1，于是曲线阶
N = p+1 完全光滑。Pohlig-Hellman 把 ECDLP 拆成每个小子群上的微型 BSGS
（每个 ≤ 2^7 步点加），强曲线的指数级难度荡然无存。

## 利用思路
1. 读 ecc.json 得 p, a=0, b=1, G, Q，重建曲线 E = ctfk.EC(0, 1, p)。
2. 分解曲线阶：f = ctfk.factorint(p+1)（全是小因子，试除即可完成）。
3. 逐位 Pohlig-Hellman：对每个素数幂 q^e，把 P、Q 映到 q^e 阶子群，
   固定 gamma = q^(e-1)·P（阶恰为 q），逐位解出 k mod q^e，CRT 合并
   （ctfk.EC.ec_pohlig 即按此实现）。
4. long_to_bytes(k) 即 flag 主体，输出 flag{<body>}。

## 关键代码
E = ctfk.EC(0, 1, p)
f = ctfk.factorint(p + 1)
k = E.ec_pohlig(tuple(G), tuple(Q), f)   # 逐位 PH + CRT (ctfk 已修复 e>=2 缺陷)
print("flag{" + ctfk.l2b(k).decode() + "}")

## 防御建议
- 优先使用标准曲线（P-256 / Curve25519），其阶含大素因子且经公开评估。
- 自定义曲线必须审查：阶的素因子结构（防 Pohlig-Hellman）、超奇异/低嵌入度
  （防 MOV 攻击）、反常曲线 (t=1) 等。
- 把"阶的光滑性检查"固化为密钥生成流水线的强制步骤，禁止反向凑参数。
