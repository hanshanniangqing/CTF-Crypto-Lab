# ecb-byte-at-a-time — 题解

> symmetric / 中等 / 250 分 / 考点: ECB 模式逐字节爆破 (chosen plaintext)

## 漏洞点
ECB 是确定性模式: 相同明文块永远映射到相同密文块。服务端把「固定 32 字节
前缀 + 攻击者输入 + flag」整体加密后回显, 于是攻击者可以让 flag 的第 j 个
字节恰好落在某个密文块的末尾, 再用 256 个候选构造出相同块的明文——密文块
相等即候选命中, 逐字节榨出 flag, 全程无需恢复密钥。

## 利用思路
1. 连接服务端, 从横幅读取前缀长度 32 (恰为 2 个块, flag 从块边界开始)。
2. 恢复第 j 个字节: 发送 b"A"*L (取 L ≡ 15-j (mod 16) 且 L ≥ 16),
   使 flag[0..j] 恰好落入块号 k = (32+L+j)//16 的末尾, 记下真实块。
3. 字典查询: 一次发送 256 组 b"A"*L + 已恢复前缀 + c 的串接
   (每组长度 L+j+1 ≡ 0 (mod 16), 各候选块自动对齐), 取对应位置的块
   与真实块比对, 相等的 c 即 flag[j]。
4. 重复直到读出 '}', 每个 flag 字节只需 2 次查询。

## 关键代码
L = ((15 - j) % 16) + 16                  # 对齐: L + j ≡ 15 (mod 16)
k = (32 + L + j) // 16
real = blockify(oracle(b"A" * L))[k]
payload = b"".join(b"A"*L + known + bytes([c]) for c in range(256))
dblocks = blockify(oracle(payload))
c = next(c for c in range(256) if dblocks[k + c*((L+j+1)//16)] == real)

## 防御建议
- 弃用 ECB, 改用带随机 nonce 的认证加密 (GCM / ChaCha20-Poly1305)。
- 不要把攻击者可控输入与机密拼进同一份明文加密; 至少在两者之间加入
  随机长度填充, 破坏块对齐。
- 对预言机接口做速率限制, 检测高频查询模式。
