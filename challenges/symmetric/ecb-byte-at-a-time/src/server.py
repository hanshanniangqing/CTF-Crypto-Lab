#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ecb-byte-at-a-time —— ECB 加密预言机 (line 协议)
#
# 用法: python server.py --port N   (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端发送:  ECB-ORACLE ready. prefix length = 32
#   客户端每次发送:        ENC <hex data>
#   服务端回答:            AES-128-ECB( PREFIX || data || FLAG ) 的 hex,
#                          加密前对整体做 pkcs7 填充。
#                          PREFIX 是启动时生成的 32 字节随机前缀, 进程存续
#                          期间固定不变 (长度恰好为 2 个块)。
#   发送 QUIT 或断开连接结束会话。
import argparse
import os
import socket
import sys

from Crypto.Cipher import AES

FLAG = 'flag{ecb_oracle_penguin_party}'
KEY = os.urandom(16)
PREFIX = os.urandom(32)   # 进程存续期间固定, 长度 32


def pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def handle(conn):
    conn.sendall(b"ECB-ORACLE ready. prefix length = 32\n")
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "ENC" and len(parts) > 1:
                try:
                    x = bytes.fromhex(parts[1])
                except ValueError:
                    conn.sendall(b"ERR\n")
                    continue
                if len(x) > 1000000:
                    conn.sendall(b"ERR\n")
                    continue
                buf = pkcs7_pad(PREFIX + x + FLAG.encode())
                conn.sendall(AES.new(KEY, AES.MODE_ECB).encrypt(buf).hex().encode() + b"\n")
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
