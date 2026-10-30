"""题解：md5-length-extension
## 漏洞点
MAC = MD5(secret || message) 是 secret-prefix MAC。MD5 是 Merkle-Damgård
结构，digest 恰是"消息末块处理完后的链式状态"，因此知道 md5(secret||m) 与
|secret||m| 的总长度后，无需知道 secret 就能从该状态继续压缩：
md5(secret||m||glue||suffix) 可由旧 digest 直接算出——这就是长度扩展攻击。
爆破 secret 长度（glue padding 依赖它）即可伪造任意追加内容的合法 MAC。

## 利用思路
1. 连接 server.py（--port 0，读 READY 行拿端口），收到
   "MAC for data=<hex>: <mac>"，解析出 content 与 digest。
2. secret 长度未知：对 L = 8..32 逐一尝试。
3. ctfk.md5_lenext(digest, L + len(content), b";admin=true") 返回
   (appendix, new_mac)，满足 md5(secret||content||appendix) = new_mac，
   且 appendix 以 glue padding 开头、含 ;admin=true。
4. 发送 SUBMIT content||appendix 与 new_mac；正确的 L 返回 GRANTED <flag>。

## 关键代码
for L in range(8, 33):
    appendix, nd = ctfk.md5_lenext(digest, L + len(content), b";admin=true")
    f.write(("SUBMIT %s %s\\n" % ((content + appendix).hex(), nd.hex())).encode())
    reply = f.readline().decode().strip()
    if reply.startswith("GRANTED"):
        print(reply.split(None, 1)[1]); break

## 防御建议
- 改用 HMAC（H(k⊕opad) || H(k⊕ipad||m)），双层结构天然免疫长度扩展。
- 或使用 SHA-3 / BLAKE3 等非 Merkle-Damgård 结构的哈希构造 MAC。
- 绝不使用 hash(secret||message) 形式的 MAC；密钥也不应硬编码在源码里。
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


def main():
    proc = subprocess.Popen([sys.executable, "server.py", "--port", "0"],
                            cwd=os.getcwd(), stdout=subprocess.PIPE)
    try:
        ready = proc.stdout.readline().decode().strip()
        assert ready.startswith("READY"), ready
        port = int(ready.split()[1])
        time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            f = s.makefile("rwb")
            line = f.readline().decode().strip()
            body = line[len("MAC for data="):]
            content_hex, digest_hex = body.rsplit(": ", 1)
            content = bytes.fromhex(content_hex)
            digest = bytes.fromhex(digest_hex)
            for secret_len in range(8, 33):
                appendix, new_mac = ctfk.md5_lenext(
                    digest, secret_len + len(content), b";admin=true")
                data = content + appendix
                f.write(("SUBMIT %s %s\n" % (data.hex(), new_mac.hex())).encode())
                f.flush()
                reply = f.readline().decode().strip()
                if reply.startswith("GRANTED"):
                    print(reply.split(None, 1)[1])
                    return
            print("attack failed: no GRANTED")
        finally:
            s.close()
    finally:
        proc.kill()


if __name__ == "__main__":
    main()
