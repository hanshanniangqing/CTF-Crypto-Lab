"""题解：rsa-lsb-oracle
## 漏洞点
解密服务充当「最低位预言机」：对任意提交的密文返回其明文 mod n
的最低位。RSA 乘法同态性允许把明文乘 2^i（发 c·(2^i)^e mod n），
于是每轮询问泄露 LSB(m·2^i mod n)。由于 m·2^i 是偶数而 n 是奇数，
m·2^i mod n = m·2^i - k·n 的奇偶性等于商 k = floor(m·2^i/n) 的
奇偶性——即 m/n 二进制展开的第 i 位。log2(n) 轮询问即可二分出 m。

## 利用思路
1. 启动 server.py（--port 0），读 READY 行取得端口。
2. 连接后读取 PUB 行得到 n, e, c。
3. 维护区间索引 a（m ∈ [a·n/2^i, (a+1)·n/2^i)）：第 i 轮发送
   cc = c·(2^i)^e mod n，取回答 bit，更新 a = 2a + bit。
4. 全部 L = n.bit_length() 轮后区间宽度 < 1，m = ceil(a·n / 2^L)。
5. 校验 m^e mod n == c（加密回去对得上），转回字节输出。

## 关键代码
two_e = pow(2, e, n)
for i in range(1, L + 1):
    cc = cc * two_e % n        # cc = c·(2^i)^e mod n
    sock.sendall(b"QUERY %x\n" % cc)
    a = 2 * a + int(rfile.readline().strip())
m = (a * n + (1 << L) - 1) >> L   # ceil(a·n / 2^L)

## 防御建议
- 解密服务不得向调用方返回明文的任何部分信息（包括奇偶、长度、格式错误细节）。
- 使用 RSA-OAEP：被篡改密文的「解密结果」没有可利用的代数结构，且填充校验失败应统一报错。
- 对解密接口做请求频率限制与密文合法性检查，异常模式直接断连。
"""
import os
import pathlib
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk
from Crypto.Util.number import long_to_bytes


def main():
    proc = subprocess.Popen([sys.executable, "server.py", "--port", "0"],
                            cwd=os.getcwd(), stdout=subprocess.PIPE)
    try:
        ready = proc.stdout.readline().decode().strip()
        if not ready.startswith("READY"):
            raise RuntimeError(f"server did not start: {ready!r}")
        port = int(ready.split()[1])
        time.sleep(0.05)
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        rfile = sock.makefile("r")
        pub = rfile.readline().strip()
        assert pub.startswith("PUB"), pub
        kv = dict(tok.split("=", 1) for tok in pub.split()[1:])
        n = int(kv["n"], 16)
        e = int(kv["e"])
        c = int(kv["c"], 16)

        L = n.bit_length()
        two_e = pow(2, e, n)
        a = 0
        cc = c
        for _ in range(L):
            cc = cc * two_e % n          # cc = (m·2^i)^e mod n
            sock.sendall(b"QUERY %x\n" % cc)
            ans = rfile.readline().strip()
            a = 2 * a + int(ans)
        m = (a * n + (1 << L) - 1) >> L  # ceil(a·n / 2^L), 区间宽度已 < 1
        assert pow(m, e, n) == c, "parity recovery failed"
        print(long_to_bytes(m).decode())
    finally:
        proc.kill()


if __name__ == "__main__":
    main()
