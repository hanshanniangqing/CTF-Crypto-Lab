# -*- coding: utf-8 -*-
"""MD5 碰撞校验器。

在当前工作目录读取 good.bin 与 evil.bin, 要求:
  * 两者 MD5 完全相同
  * 两者 SHA256 不同 (即不能是同一个文件)
  * good.bin 以 colliding_base_1.bin 的内容开头
  * evil.bin 以 colliding_base_2.bin 的内容开头
  * 两者长度都超过 200 字节 (不能直接提交原始碰撞块)
全部通过则输出 flag。
"""
import hashlib
import sys

GOOD_BASE = open("colliding_base_1.bin", "rb").read()
EVIL_BASE = open("colliding_base_2.bin", "rb").read()
FLAG = "flag{md5_collision_classic}"


def die(msg):
    print("VERIFY-FAIL: " + msg)
    sys.exit(1)


def load(fn, base):
    try:
        data = open(fn, "rb").read()
    except OSError as e:
        die("无法读取 %s: %s" % (fn, e))
    if len(data) <= 200:
        die("%s 长度 %d 未超过 200 字节" % (fn, len(data)))
    if not data.startswith(base):
        die("%s 未以对应的 colliding_base 开头" % fn)
    return data


good = load("good.bin", GOOD_BASE)
evil = load("evil.bin", EVIL_BASE)
if hashlib.md5(good).digest() != hashlib.md5(evil).digest():
    die("两文件的 MD5 不相同")
if hashlib.sha256(good).digest() == hashlib.sha256(evil).digest():
    die("两文件 SHA256 相同 (内容一样?)")
print(FLAG)
