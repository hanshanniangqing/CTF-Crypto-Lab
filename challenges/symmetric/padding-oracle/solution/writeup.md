# padding-oracle — 题解

> symmetric / 困难 / 350 分 / 考点: CBC Padding Oracle 攻击

## 漏洞点
服务端解密 CBC 密文后泄漏「pkcs7 填充是否合法」这 1 比特。对最后一个块
P = D(C_n) XOR C_{n-1}, 填充只由解密结果的尾部字节决定, 而 C_{n-1} 完全
由攻击者控制: 构造 C_{n-1} 使解密尾部恰为合法填充, 用 ≤256 次询问即可
确定中间值 D(C_n) 的一个字节——一比特预言机足以完整解密。

## 利用思路
1. 连接服务端, 接收 CT 行, 拆出 iv 与密文块 C1..C3。
2. 对每个目标块 C_i (其前块为 C_{i-1}, 首块用 IV), 从最后一字节向前恢复
   中间值 I = D(C_i): 已确定 I 的后缀后, 构造 C_{i-1}' 使 P' 的尾部恰为
   长度 padlen = 16-i 的合法填充; 唯一使预言机回 OK 的字节给出
   I[i] = g XOR padlen。
3. 最后一字节可能歧义 (0x01 与恰好也合法的更长填充), 扰动倒数第二字节
   重测即可甄别。
4. 明文块 P_i = I XOR C_{i-1}; 拼接全部块, 去 pkcs7 填充得 flag。

## 关键代码
for i in range(15, -1, -1):
    padlen = 16 - i
    prev = bytearray(c_prev)
    for kk in range(i + 1, 16):
        prev[kk] = mid[kk] ^ padlen
    g = 唯一使 oracle(bytes(prev[:i]) + bytes([g]) + ... + c_target) 回 OK 的字节
    mid[i] = g ^ padlen
plain += xor(mid, c_prev)

## 防御建议
- 使用认证加密 (GCM / Encrypt-then-MAC): MAC 校验失败时直接拒绝,
  不向攻击者暴露填充信息, padding oracle 从根本上消失。
- 若必须返回错误, 统一所有解密失败的响应, 不区分填充错误与其它错误。
- 对单客户端的 DEC 查询频率限速并监控 (本攻击需要上万次询问)。
