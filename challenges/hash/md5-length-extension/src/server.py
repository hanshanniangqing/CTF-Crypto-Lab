# -*- coding: utf-8 -*-
"""MD5 长度扩展挑战服务器 (secret-prefix MAC)。

启动: python server.py --port N   (--port 0 表示由系统分配端口)
行协议:
  连接后服务器先发送一行:
      MAC for data=<content 的 hex>: <md5(secret||content) 的 hex>
  之后客户端每发送一行: SUBMIT <data 的 hex> <mac 的 hex>
  服务器检查: data 须以原始 content 开头, 且包含 b";admin=true",
              且 md5(secret||data) == mac。
  通过则回 GRANTED <flag>, 否则回 REJECTED。

⚠️ 安全反模式说明: 真实系统绝不应把密钥硬编码在源码里。本文件出于教学
目的将 SECRET 以逐字节 XOR 0x5A 的混淆形式存放 (你可以读出来, 这允许;
但本题的标准解法是 MD5 长度扩展攻击 —— 不需要知道密钥本身)。
"""
import argparse
import hashlib
import socket
import sys

_ENC = [9, 105, 57, 40, 105, 46, 23, 27, 25, 49, 105, 35, 104, 106, 104, 108]
SECRET = bytes(b ^ 0x5A for b in _ENC)
CONTENT = b"amount=100;to=alice;"
FLAG = "flag{glue_padding_sticks}"


def mac(data):
    return hashlib.md5(SECRET + data).hexdigest()


def handle(conn):
    f = conn.makefile("rwb")
    try:
        f.write(("MAC for data=%s: %s\n" % (CONTENT.hex(), mac(CONTENT))).encode())
        f.flush()
        while True:
            raw = f.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3 or parts[0] != "SUBMIT":
                f.write(b"BADREQ\n")
                f.flush()
                continue
            try:
                data = bytes.fromhex(parts[1])
                given = parts[2].lower()
            except ValueError:
                f.write(b"BADREQ\n")
                f.flush()
                continue
            ok = (data.startswith(CONTENT)
                  and b";admin=true" in data
                  and hashlib.md5(SECRET + data).hexdigest() == given)
            f.write((("GRANTED " + FLAG if ok else "REJECTED") + "\n").encode())
            f.flush()
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(5)
    sys.stdout.write("READY %d\n" % srv.getsockname()[1])
    sys.stdout.flush()
    while True:
        conn, _addr = srv.accept()
        handle(conn)


if __name__ == "__main__":
    main()
