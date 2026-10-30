# mt19937-clone — 题解

> stream / 中等 / 250 分 / 考点: MT19937 状态克隆 (untemper)

## 漏洞点
MT19937 的每个 32 位输出都是内部状态字经过 tempering 得到的, 而
tempering 的每一步 (右移异或、左移掩码异或) 都是可逆的。因此拿到
624 个连续输出 (恰好等于内部状态数组的长度) 就能逐个 untemper 还原
全部内部状态, 完整克隆生成器——之后所有「随机」输出都成了预言。

## 利用思路
1. 读 outputs.txt 得到 624 个连续输出。
2. 对每个输出做 untemper, 得到内部状态 mt[0..623]。
3. 用这些状态重建生成器 (ctfk.clone_mt 内部就是
   set_state([untemper(y) for y in outputs])), 其后续输出与原生成器
   完全一致。
4. 克隆体继续产出 24 字节「密钥流」, 与 flag.enc 异或即得 flag。

## 关键代码
outs = [int(x) for x in open("outputs.txt").read().split()]
clone = ctfk.clone_mt(outs)                 # 624 个输出 -> 完整克隆
ks = clone.next_bytes(len(ct))
print(ctfk.xor_bytes(ct, ks).decode())

## 防御建议
- MT19937 是统计模拟用的 PRNG, 不是密码学安全的; 安全场景必须换成
  CSPRNG (secrets / os.urandom / ChaCha20-DRBG)。
- 不要把生成器原始输出直接暴露 (日志、接口回显、token 可预测性检测)。
- 若必须使用 MT, 至少限制单一个体能观测的连续输出数量并定期重播种。
