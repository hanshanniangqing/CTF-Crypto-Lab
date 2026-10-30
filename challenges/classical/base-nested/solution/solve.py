"""题解：base-nested
## 漏洞点
密文只是被反复套上了常见编码 (hex / base32 / base64 / ascii85), 每一层都有
明显的字符集与格式特征: hex 是偶长的 0-9a-f, base32 是 A-Z2-7 加 '=' 补位,
base64 是 A-Za-z0-9+/, ascii85 落在 '!'..'u' 的可打印区间。编码只是格式转换,
不具备任何保密性, 嵌套多少层都只是增加剥壳次数。

## 利用思路
1. 读入 encoded.txt, 对当前字符串按特征匹配可能的编码。
2. 依次尝试解码, 只有当解出的字节仍是可打印 ASCII 时才接受这一层
   (防止把 base64 误判成 hex 之类的误剥)。
3. 重复剥壳直到没有任何编码特征匹配, 在最内层文本中用正则提取 flag{...}。
   (也可以直接用 ctfk.try_decode_layers 自动剥壳。)

## 关键代码
for name, pat, fn in DECODERS:          # 按 hex->base32->base64->a85 顺序
    if not re.fullmatch(pat, s): continue
    cand = fn(s)
    if printable(cand):                 # 只接受可打印结果, 防误剥
        cur, s = cand, cand.decode("ascii", "replace")
        break

## 防御建议
- 编码不是加密: Base16/32/64/85 只解决传输兼容问题, 不提供机密性。
- 需要保密时使用带密钥的标准算法 (AES-GCM、ChaCha20-Poly1305 等)。
- 传输编码数据时叠加真正的加密与完整性校验, 避免让人误以为是保护措施。
"""
import base64
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk


def printable(b):
    return bool(b) and all(32 <= x <= 126 or x in (9, 10, 13) for x in b)


DECODERS = (
    ("hex", r"(?:[0-9a-fA-F]{2})+", lambda s: bytes.fromhex(s)),
    ("base32", r"[A-Za-z2-7]+={0,6}",
     lambda s: base64.b32decode(s, casefold=True)),
    ("base64", r"[A-Za-z0-9+/]+={0,2}",
     lambda s: base64.b64decode(s, validate=True)),
    ("ascii85", r"[!-u]+", lambda s: base64.a85decode(s)),
)


def peel(data, max_layers=16):
    cur = data
    for _ in range(max_layers):
        try:
            s = cur.decode("ascii").strip()
        except (UnicodeDecodeError, AttributeError):
            break
        if not s:
            break
        nxt = None
        for _, pat, fn in DECODERS:
            if not re.fullmatch(pat, s):
                continue
            try:
                cand = fn(s)
            except Exception:
                continue
            if printable(cand):
                nxt = cand
                break
        if nxt is None:
            break
        cur = nxt
    return cur


def main():
    data = open("encoded.txt", "rb").read()
    text = peel(data).decode("ascii", "replace")
    m = re.search(r"flag\{[^}]*\}", text)
    if not m:  # 兜底: 工具箱自动剥壳
        inner = ctfk.try_decode_layers(data)[0].decode("ascii", "replace")
        m = re.search(r"flag\{[^}]*\}", inner)
    assert m, "未能在最内层文本中找到 flag"
    print(m.group(0))


if __name__ == "__main__":
    main()
