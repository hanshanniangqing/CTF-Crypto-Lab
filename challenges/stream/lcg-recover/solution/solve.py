"""题解：lcg-recover
## 漏洞点
线性同余生成器 x_{i+1} = (a·x_i + c) mod m 的状态转移完全线性。给出
若干个连续输出后: 相邻差分 d_i = x_{i+1} - x_i 满足 d_{i+1} ≡ a·d_i,
因此 m 整除 t_i = d_{i+2}·d_i - d_{i+1}², 对多个 i 求 gcd 即得 m;
随后 a = (x2-x1)·inv(x1-x0) mod m, c = x1 - a·x0——8 个输出就足以
把整个生成器 (含未来全部输出) 交给攻击者。

## 利用思路
1. 从 output.txt 解析 8 个十进制输出 o1..o8。
2. ctfk.solve_lcg_params(o1..o8) 恢复 (m, a, c)。
3. 以 o8 为当前状态继续步进 4 次, 得到「接下来的 4 个输出」。
4. 每个输出按 8 字节大端编码后连接成 32 字节 pad, 与 mask.txt 异或,
   去掉尾部 NUL 字节即得 flag。

## 关键代码
params = ctfk.solve_lcg_params(outs)      # -> (m, a, c)
lcg = ctfk.LCG(a, c, m, outs[-1])
pad = 持续步进直到凑满 len(mask) 字节
flag = ctfk.xor_bytes(pad, mask).rstrip(b"\\x00")

## 防御建议
- 任何线性同余生成器都不是 CSPRNG, 输出不可对外公开;
  安全用途请用 secrets / os.urandom 或 ChaCha20-DRBG。
- 必须用 LCG 做模拟/游戏时, 不要把原始状态直接回显, 或至少做单向混淆。
- 对外暴露的「随机数服务」应审计其生成算法与可预测性。
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def main():
    outs = []
    for line in open("output.txt", encoding="utf-8"):
        mm = re.match(r"\s*o(\d+)\s*=\s*(\d+)", line)
        if mm:
            outs.append(int(mm.group(2)))
    assert len(outs) >= 6, "need at least 6 consecutive outputs"
    params = ctfk.solve_lcg_params(outs)
    assert params, "failed to recover LCG parameters"
    mod, a, c = params
    mask = bytes.fromhex("".join(open("mask.txt").read().split()))
    lcg = ctfk.LCG(a, c, mod, outs[-1])
    chunks = []
    while sum(len(x) for x in chunks) < len(mask):
        chunks.append(lcg.next().to_bytes(8, "big"))
    pad = b"".join(chunks)[: len(mask)]
    print(ctfk.xor_bytes(pad, mask).rstrip(b"\x00").decode())


main()
