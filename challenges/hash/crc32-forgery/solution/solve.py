"""题解：crc32-forgery
## 漏洞点
CRC32 是 GF(2) 上的线性函数：固定前缀时，crc(prefix || s) 随 4 字节后缀 s
的每一个比特线性变化。给定任意前缀与任意目标 CRC，把它写成 32 个线性方程
用高斯消元即可解出唯一的 4 字节补丁 s。因此"校验和一致"只能检测随机传输
错误，完全不能抵抗恶意篡改——CRC 不是哈希，更不是 MAC。

## 利用思路
1. 读 appeal.txt，计算其 CRC32 作为目标值。
2. 选一段包含 "ACCESS GRANTED" 且不含 "guest" 的新前缀，长度也与原信不同。
3. ctfk.crc32_patch(prefix, target) 解 GF(2) 线性方程组，返回 4 字节补丁。
4. 写 forged.txt = prefix + patch，运行 verify.py 打印 flag。

## 关键代码
patch = ctfk.crc32_patch(prefix, zlib.crc32(appeal))
open("forged.txt", "wb").write(prefix + patch)
out = subprocess.run([sys.executable, "verify.py"],
                     capture_output=True, text=True).stdout
print(out.strip())

## 防御建议
- 完整性校验用加密哈希 (SHA-256)；防篡改必须用 MAC (HMAC) 或数字签名。
- CRC32 只保留给链路层检错这类"仅防比特翻转"的场景。
- 固件/文件分发使用签名清单，任何"改内容但保校验和"的请求都应被拒绝。
"""
import pathlib
import subprocess
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    appeal = open("appeal.txt", "rb").read()
    target = zlib.crc32(appeal) & 0xFFFFFFFF
    prefix = b"Dear admin, ACCESS GRANTED for user hero."
    patch = ctfk.crc32_patch(prefix, target)
    assert patch is not None, "GF(2) 方程组无解"
    forged = prefix + patch
    assert zlib.crc32(forged) == target
    assert b"ACCESS GRANTED" in forged and b"guest" not in forged
    assert len(forged) != len(appeal)
    open("forged.txt", "wb").write(forged)
    r = subprocess.run([sys.executable, "verify.py"],
                       capture_output=True, text=True, timeout=60)
    print(r.stdout.strip())


if __name__ == "__main__":
    main()
