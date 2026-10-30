# lcg-truncated — 题解

> stream / 中等 / 250 分 / 考点: 截断 LCG 状态恢复 (格 / Babai)

## 漏洞点
LCG 的参数 (m, a, c) 全部公开, 但每个输出只泄露高 32 位、低 32 位被丢弃。
未知量是一串「小」变量 l_i (每项 < 2^32), 而状态转移仍是线性的:
l_{i+1} ≡ a·l_i + (a·h_i - h_{i+1})·2^32 + c (mod m)。这是典型的
隐数问题, 可以直接写成格上的 CVP/BDD——用 LLL 约减后 Babai 最近平面
即可把所有丢失的低位一次性找回来。

## 利用思路
1. 从 source.py 读出 (M, A, C), 从 outputs.txt 读 16 个高 32 位 (hex)。
2. ctfk.solve_lcg_truncated(M, A, C, highs, 32) 在格上恢复全部完整状态
   (内部: 构造 l_i = a^i·l_0 + d_i 的格基, Babai 逼近小向量, 再验证
   递推与高位约束)。
3. 取恢复出的最后一个状态作为当前种子, 继续步进 4 次。
4. 4 个输出按 8 字节大端连接成 32 字节 pad, 与 mask.txt 异或,
   去尾部 NUL 即得 flag。

## 关键代码
states = ctfk.solve_lcg_truncated(M, A, C, highs, 32)
lcg = ctfk.LCG(A, C, M, states[-1])
pad = 持续步进直到凑满 len(mask) 字节
flag = ctfk.xor_bytes(pad, mask).rstrip(b"\x00")

## 防御建议
- 截断输出救不了线性生成器: 只要泄露的位数 × 输出个数足以构成
  超定方程组, 格攻击就能恢复状态; 干脆不要暴露原始输出。
- 安全用途必须使用 CSPRNG (secrets / os.urandom)。
- 若业务上必须输出部分位, 应监控异常查询并在泄露达到阈值前轮换状态。
