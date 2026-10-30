#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 本地签名验证器 (教科书式 RSA: e = 3, 无填充, 无哈希).
# 读取同目录 sig.txt 中的十六进制签名, 立方后检查字节前缀。
MSG_PREFIX = b"I am the admin"
FLAG = 'flag{cube_root_signature}'
N = 0x984dea73c3cdb109e09e7bbca2b18f45767340896c6ec3bbe8353b5717e178fce3ccf006fdb6b5bb8b56c9ec4f1fc1028b13e65b8668336cd50e593a48d6f343d703201d58336882a712dda161936970ec89e118e2e86b2f11bd832ac1f23ce1fd5a3f5e002fd9754e910028e09490734c6121fac9b7078339767e0dba29dfcb
E = 3


def main():
    try:
        s = int(open("sig.txt").read().strip(), 16)
    except Exception:
        print("REJECTED (cannot read sig.txt)")
        return
    m = pow(s, E, N)
    mb = m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b""
    if mb.startswith(MSG_PREFIX):
        print(FLAG)
    else:
        print("REJECTED")


if __name__ == "__main__":
    main()
