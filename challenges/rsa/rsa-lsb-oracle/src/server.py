#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rsa-lsb-oracle 解密服务 (line 协议).
#
# 用法: python server.py --port N    (--port 0 = 系统自动分配端口)
# 协议:
#   连接建立后服务端立刻发送一行:  PUB n=<hex> e=<十进制> c=<hex>
#   客户端每次发送一行:            QUERY <hex 密文>
#   服务端回答一行:                该密文解密结果 (mod n) 的最低位, "0" 或 "1"
#   发送 QUIT 或断开连接结束本次会话。
import argparse
import socket
import sys

P = 0x910d3c82aafe2514a0ea2ba151899829005159e6446ad4a1c9010fd97dd8ffe3
Q = 0xd7f0711a0d9a392f913fccb7181adbb5cf5ff82c06bb7e6ee7502e52478398e9
C = 0x525f675e7b146ad84a53af1d78b7cda0865cc44e6614d1871ea3e5e1c5e6460c56e587dce766d00c99e68dc098b1668460d8c495eaf03e9cfd19468b1595ae19
E = 65537
N = P * Q
D = pow(E, -1, (P - 1) * (Q - 1))


def handle(conn):
    conn.sendall(("PUB n=%x e=%d c=%x\n" % (N, E, C)).encode())
    rfile = conn.makefile("r")
    try:
        for line in rfile:
            parts = line.split()
            if not parts:
                continue
            if parts[0].upper() == "QUERY" and len(parts) > 1:
                try:
                    mm = pow(int(parts[1], 16), D, N)
                    conn.sendall(b"%d\n" % (mm & 1))
                except ValueError:
                    conn.sendall(b"ERR\n")
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
