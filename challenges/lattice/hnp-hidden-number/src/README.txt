hnp-hidden-number 附件说明
==========================
samples.json 内容:
  p        : 256-bit 素数
  samples  : 14 个样本 [a_i, b_i, leak_i] (均为十进制整数)

侧信道对秘密 x 每次采样给出:
  v    = (a*x + b) mod p
  leak = v >> 224   (即 v 的最高 32 位; 低 224 位未知)

也就是每条样本泄露了 x 在随机掩码 a 下的约 32 bit 信息,14 条样本共 448 bit, 足以把 x 完全格出来。
