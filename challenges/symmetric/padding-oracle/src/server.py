#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# padding-oracle —— CBC 解密填充预言机 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  CT <hex iv><hex c1><hex c2><hex c3>
#   客户端每次发送:        DEC <hex data>
#                          data = iv' || 若干个 16 字节密文块
#   服务端以 iv' 为 IV 做 CBC 解密, 检查明文尾部的 pkcs7 填充:
#                          OK    (填充合法)
#                          ERR   (填充非法 / 请求格式错误)
#   发送 QUIT 或断开连接结束会话。
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = 'flag{padding_oracle_padawan_no_more}'
KEY = os.urandom(16)
IV = os.urandom(16)


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_valid(data, block=16):
    if not data or len(data) % block:
        return False
    n = data[-1]
    return 1 <= n <= block and data[-n:] == bytes([n]) * n


PT = pkcs7_pad(FLAG.encode())
CT = AES.new(KEY, AES.MODE_CBC, IV).encrypt(PT)


def handle(conn):
    conn.sendall(("CT %s%s\n" % (IV.hex(), CT.hex())).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "DEC" and len(parts) > 1:
                try:
                    data = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(data) < 32 or (len(data) - 16) % 16:
                    conn.sendall(b"ERR\n")
                    continue
                pt = AES.new(KEY, AES.MODE_CBC, data[:16]).decrypt(data[16:])
                conn.sendall(b"OK\n" if pkcs7_valid(pt) else b"ERR\n")
            elif parts[0].upper() in ("QUIT", "EXIT"):
                break
    except OSError:
        pass
    finally:
        try:
            rfile.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(4)
    port = srv.getsockname()[1]
    sys.stdout.write("READY %d\n" % port)
    sys.stdout.flush()
    try:
        while True:
            conn, _ = srv.accept()
            try:
                handle(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
