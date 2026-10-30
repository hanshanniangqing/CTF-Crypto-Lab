lwe-toy 附件说明
================
这是一个玩具级的 Regev 型 LWE 实例:
  q = 251, n = 5, m = 24
  秘密 s_j ∈ {-1, 0, 1}        (极小秘密)
  噪声 e_i ∈ [-3, 3]           (极小噪声)
  b_i = (sum_j A[i][j]*s[j] + e_i) mod q

lwe.json 字段:
  q, n, m : 参数
  A       : m x n 公开矩阵 (元素 ∈ [0, q))
  b       : m 维样本向量
  ct      : flag 密文 (hex)

flag 的加密方式 (恢复 s 后即可解):
  key      = SHA256(bytes(s_j + 1 for j in 0..n-1))
  keystream: 从 key 开始反复 SHA256 链式拼接, 截取前 len(flag) 字节
             (ks = b""; prev = key; while len(ks) < L: prev = SHA256(prev); ks += prev)
  ct       = flag XOR keystream

噪声和秘密都极小, (e, s) 可以一起放进 Kannan 嵌入格, LLL 一击即中。
