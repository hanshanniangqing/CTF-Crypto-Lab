#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cbc-bitflip —— 令牌授权服务 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  TOKEN <hex iv><hex ct>
#   客户端每次发送:        ATTEMPT <hex iv'>
#   服务端用【原密文 ct】+ 新 IV 解密, 检查明文是否提权为 admin:
#                          GRANTED <flag>   (明文中出现 ROLE=admin 或 USER=admin)
#                          DENIED           (否则) / ERR (请求格式错误)
#   发送 QUIT 或断开连接结束会话。
#
# 令牌明文固定为: USER=guest;ROLE=user;EXP=20301231
# (33 字节, pkcs7 填充到 48 字节 = 3 个 AES 块)
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = 'flag{flip_bits_not_tables}'
KEY = os.urandom(16)
TOKEN_PLAIN = b"USER=guest;ROLE=user;EXP=20301231"


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def handle(conn):
    iv = os.urandom(16)
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pkcs7_pad(TOKEN_PLAIN))
    conn.sendall(("TOKEN %s%s\n" % (iv.hex(), ct.hex())).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "ATTEMPT" and len(parts) > 1:
                try:
                    iv2 = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(iv2) != 16:
                    conn.sendall(b"ERR\n")
                    continue
                pt = AES.new(KEY, AES.MODE_CBC, iv2).decrypt(ct)
                if b"ROLE=admin" in pt or b"USER=admin" in pt:
                    conn.sendall(("GRANTED %s\n" % FLAG).encode())
                else:
                    conn.sendall(b"DENIED\n")
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
