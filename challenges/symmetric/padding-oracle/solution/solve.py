"""题解：padding-oracle
## 漏洞点
服务端解密 CBC 密文后泄漏「pkcs7 填充是否合法」这 1 比特。对最后一个块
P = D(C_n) XOR C_{n-1}, 填充只由解密结果的尾部字节决定, 而 C_{n-1} 完全
由攻击者控制: 构造 C_{n-1} 使解密尾部恰为合法填充, 用 ≤256 次询问即可
确定中间值 D(C_n) 的一个字节——一比特预言机足以完整解密。

## 利用思路
1. 连接服务端, 接收 CT 行, 拆出 iv 与密文块 C1..C3。
2. 对每个目标块 C_i (其前块为 C_{i-1}, 首块用 IV), 从最后一字节向前恢复
   中间值 I = D(C_i): 已确定 I 的后缀后, 构造 C_{i-1}' 使 P' 的尾部恰为
   长度 padlen = 16-i 的合法填充; 唯一使预言机回 OK 的字节给出
   I[i] = g XOR padlen。
3. 最后一字节可能歧义 (0x01 与恰好也合法的更长填充), 扰动倒数第二字节
   重测即可甄别。
4. 明文块 P_i = I XOR C_{i-1}; 拼接全部块, 去 pkcs7 填充得 flag。

## 关键代码
for i in range(15, -1, -1):
    padlen = 16 - i
    prev = bytearray(c_prev)
    for kk in range(i + 1, 16):
        prev[kk] = mid[kk] ^ padlen
    g = 唯一使 oracle(bytes(prev[:i]) + bytes([g]) + ... + c_target) 回 OK 的字节
    mid[i] = g ^ padlen
plain += xor(mid, c_prev)

## 防御建议
- 使用认证加密 (GCM / Encrypt-then-MAC): MAC 校验失败时直接拒绝,
  不向攻击者暴露填充信息, padding oracle 从根本上消失。
- 若必须返回错误, 统一所有解密失败的响应, 不区分填充错误与其它错误。
- 对单客户端的 DEC 查询频率限速并监控 (本攻击需要上万次询问)。
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


def recover_mid(query, c_target, c_prev):
    """恢复中间值 D(c_target); query(data) 以 data = prev'||c_target 询问"""
    mid = [0] * 16

    def probe(i, g, tweak=None):
        p = bytearray(c_prev)
        for kk in range(i + 1, 16):
            p[kk] = mid[kk] ^ (16 - i)
        if tweak is not None:
            p[14] ^= tweak
        p[i] = g
        return query(bytes(p) + c_target)

    for i in range(15, -1, -1):
        cands = [g for g in range(256) if probe(i, g)]
        if len(cands) > 1:
            good = None
            for t in range(1, 256):
                good = [g for g in cands if probe(i, g, tweak=t)]
                if len(good) == 1:
                    break
            cands = good
        if len(cands) != 1:
            raise RuntimeError("oracle ambiguity at byte %d" % i)
        mid[i] = cands[0] ^ (16 - i)
    return bytes(mid)


def main():
    proc = subprocess.Popen([sys.executable, "server.py", "--port", "0"],
                            cwd=os.getcwd(), stdout=subprocess.PIPE)
    try:
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("READY"), line
        port = int(line.split()[1])
        time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        rf = s.makefile("r")
        head = rf.readline().strip()            # CT <hex iv><hex ct>
        assert head.startswith("CT "), head
        blob = head.split(" ", 1)[1]
        iv = bytes.fromhex(blob[:32])
        ct = bytes.fromhex(blob[32:])
        blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]

        def query(data):
            s.sendall(b"DEC " + data.hex().encode() + b"\n")
            return rf.readline().strip() == "OK"

        plain = b""
        prev = iv
        for cb in blocks:
            mid = recover_mid(query, cb, prev)
            plain += ctfk.xor_bytes(mid, prev)
            prev = cb
        print(ctfk.pkcs7_unpad(plain).decode())
    finally:
        proc.kill()


main()
