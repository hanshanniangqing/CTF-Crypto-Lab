"""题解：cbc-bitflip
## 漏洞点
CBC 解密的第一块满足 P1 = D(C1) XOR IV。IV 与密文一起传输, 而服务端
允许用新 IV 重放同一段密文——于是异或差分 Δ = P1 XOR P1' 后提交
(iv XOR Δ), 服务端解出的第一块明文就精确变成 P1'。攻击者完全不需要
密钥, 其余明文块也不受影响。

## 利用思路
1. 连接服务端, 接收 TOKEN 行, 拆出 iv 与 ct (hex)。
2. 第一块明文已知: P1 = b"USER=guest;ROLE=" (固定令牌, 无需猜测)。
3. 目标第一块 P1' = b"USER=admin;ROLE=", 计算差分 Δ = P1 XOR P1'。
4. 发送 ATTEMPT (iv XOR Δ): 服务端用原 ct 解密, 第一块即变为 P1',
   明文中出现 USER=admin, 满足 GRANTED 条件。
5. 读取 GRANTED 响应, 提取其中的 flag。

## 关键代码
delta = ctfk.xor_bytes(b"USER=guest;ROLE=", b"USER=admin;ROLE=")
new_iv = ctfk.xor_bytes(iv, delta)
sock.sendall(b"ATTEMPT " + new_iv.hex().encode() + b"\n")
resp = sock.makefile("r").readline()        # GRANTED <flag>
print(resp.split(" ", 1)[1])

## 防御建议
- 使用认证加密 (AES-GCM / Encrypt-then-MAC): 任何比特被篡改都会使
  整个密文校验失败, 而不是被悄悄改写语义。
- 不要把 IV 与「可被重放的同一密文」解耦处理; IV 应与密文绑定保护。
- 授权判断应在服务端基于签名/MAC 过的完整令牌, 而非解密文本的子串匹配。
"""
import os
import socket
import subprocess
import sys
import pathlib
import time

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    proc = subprocess.Popen([sys.executable, "server.py", "--port", "0"],
                            cwd=os.getcwd(), stdout=subprocess.PIPE)
    try:
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("READY"), line
        port = int(line.split()[1])
        time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        rf = s.makefile("r")
        tok = rf.readline().strip()                 # TOKEN <hex iv><hex ct>
        assert tok.startswith("TOKEN "), tok
        blob = tok.split(" ", 1)[1]
        iv = bytes.fromhex(blob[:32])
        p1_known = b"USER=guest;ROLE="
        p1_target = b"USER=admin;ROLE="
        delta = ctfk.xor_bytes(p1_known, p1_target)
        new_iv = ctfk.xor_bytes(iv, delta)
        s.sendall(b"ATTEMPT " + new_iv.hex().encode() + b"\n")
        resp = rf.readline().strip()
        assert resp.startswith("GRANTED"), resp
        print(resp.split(" ", 1)[1])
    finally:
        proc.kill()


main()
