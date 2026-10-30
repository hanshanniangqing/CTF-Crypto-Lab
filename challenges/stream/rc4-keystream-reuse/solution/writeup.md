# rc4-keystream-reuse — 题解

> stream / 简单 / 100 分 / 考点: RC4 密钥流重用

## 漏洞点
两条消息使用同一个 RC4 密钥, 密钥流逐字节相同。RC4 加密只是
ct = pt XOR keystream, 于是 ct1 XOR pt1 直接还原出密钥流本身, 再与
ct2 异或即得第二条消息——密钥自始至终不需要知道。这是「两本一次性
密码本用成了多次性」的经典 two-time-pad 错误。

## 利用思路
1. 读 known_plain.txt 得到 msg1 全文 (64 字节日志头), 读
   two_ciphertexts.txt 得 ct1 / ct2 (hex)。
2. keystream = ct1 XOR msg1 (前 len(ct2) 字节即够用)。
3. pt2 = ct2 XOR keystream, 明文里就带着 flag。

## 关键代码
ks = ctfk.xor_bytes(ct1, pt1)          # 还原密钥流
pt2 = ctfk.xor_bytes(ct2, ks[:len(ct2)])
print(pt2.decode())

## 防御建议
- 密钥流绝不重用: 每条消息使用新密钥, 或改用带 nonce 的算法
  (ChaCha20 / AES-GCM / CTR), 并保证 nonce 不重复。
- 可预测的日志头与机密同流加密时尤其致命, 应按记录分节、各自加随机前缀。
- RC4 本身已有强偏置漏洞, 任何新系统都不应再选用。
