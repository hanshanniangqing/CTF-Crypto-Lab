#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rng_service.py —— 某摇号服务的截断输出实现
#
# 生成器是线性同余:  x_{i+1} = (A * x_i + C) mod M
# 运维只把每个状态的高 32 位写进日志 (见 outputs.txt, 每行一个 hex 值,
# 低 32 位被丢弃)。
#
# 提示: 接下来的 5 个【完整】输出, 每个按 8 字节大端编码后依次
# 连接成 32 字节 pad, 与 mask.txt (hex) 异或即是 flag (去掉尾部 NUL)。

M = 18446744073709551557   # 2**64 - 59 (素数)
A = 708387106744700136
C = 14002139194797906591


class TruncatedLCG:
    def __init__(self, seed):
        self.s = seed % M

    def next(self):
        self.s = (A * self.s + C) % M
        return self.s

    def next_logged(self):
        return format(self.next() >> 32, "08x")
