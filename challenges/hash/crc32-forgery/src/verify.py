# -*- coding: utf-8 -*-
"""CRC32 伪造校验器。

在当前工作目录读取 forged.txt, 要求:
  * CRC32 与原始申诉信完全一致 (0x0xf7d1b9f3)
  * 内容包含 "ACCESS GRANTED"
  * 内容不包含 "guest"
  * 长度与原始申诉信不同
全部通过则输出 flag。
"""
import sys
import zlib

APPEAL = b'Dear admin, please unban user guest. Reason: he said sorry.\n'
TARGET_CRC = 0xf7d1b9f3
FLAG = "flag{crc32_is_not_a_hash}"


def die(msg):
    print("VERIFY-FAIL: " + msg)
    sys.exit(1)


try:
    forged = open("forged.txt", "rb").read()
except OSError as e:
    die("无法读取 forged.txt: %s" % e)

if zlib.crc32(forged) != TARGET_CRC:
    die("CRC32 与原始申诉信不一致")
if b"ACCESS GRANTED" not in forged:
    die("缺少 ACCESS GRANTED")
if b"guest" in forged:
    die("内容仍包含 guest")
if len(forged) == len(APPEAL):
    die("长度与原始申诉信相同")
print(FLAG)
