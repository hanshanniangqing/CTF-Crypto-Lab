"""题解：zip-crack
## 漏洞点
传统 ZipCrypto (PKZIP 流加密) 有两大死穴：口令可以离线穷举；其 12 字节加密头
的最后一个字节是 CRC 校验字节，speedup 后字典验证只需极小代价。弱口令 +
ZipCrypto = 等同明文存储。

## 利用思路
1. zip2john.exe leaked.zip 提取 john 格式哈希。
2. john --wordlist=rockyou 跑字典 (ZipCrypto 极快，分钟内覆盖千万级词表)。
3. john --show 读回口令；Python zipfile(zip, pwd=口令) 读出 flag.txt。
4. 无 John 时退化为 zipfile + rockyou 逐条尝试 (每条 ~0.1ms)。

## 关键代码
z = zipfile.ZipFile("leaked.zip")
data = z.read("flag.txt", pwd=pw.encode())   # 口令错则抛 RuntimeError

## 防御建议
- 禁用 ZipCrypto；确需压缩加密时使用 AES-256 (7-Zip/WinRAR AES)。
- 归档口令不允许出现在历史泄露字典中，走密码管理器生成。
- 邮件网关/EDR 对带密码压缩包的投递链路做标记与告警。
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))
import resources as RES  # noqa: E402

import zipfile  # noqa: E402


def via_john(res, workdir):
    home = Path(res["john"]["home"])
    z2j = home / "zip2john.exe"
    if not z2j.exists():
        z2j = home / "zip2john"
    hashf = Path(workdir) / "zip.hash"
    r = subprocess.run([str(z2j), "leaked.zip"], capture_output=True, text=True, timeout=120)
    line = (r.stdout or "").strip().splitlines()[0]
    hashf.write_text(line, encoding="utf-8")
    pot = Path(workdir) / "ctf.pot"
    john = res["john"]["exe"]
    subprocess.run([john, f"--wordlist={res['rockyou']['path']}", f"--pot={pot}", str(hashf)],
                   capture_output=True, text=True, timeout=600)
    # 解析 pot 文件 (行格式 <hash>:<password>, hash 内不含冒号)
    if pot.exists():
        for ln in pot.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in ln:
                pw_ = ln.rsplit(":", 1)[1]
                if pw_:
                    return pw_
    return None


def via_python(res):
    with zipfile.ZipFile("leaked.zip") as z:
        for w in RES.rockyou_iter(res, limit=120000):
            try:
                z.read("flag.txt", pwd=w)
                return w.decode("latin-1")
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                continue
    # 降级迷你字典
    for w in ("123456 password qwerty abc123 letmein trustno1 iloveyou monkey".split()):
        try:
            with zipfile.ZipFile("leaked.zip") as z:
                z.read("flag.txt", pwd=w.encode())
            return w
        except Exception:
            continue
    return None


def main():
    res = RES.get_resources()
    pw = None
    if res.get("john") and res.get("rockyou"):
        with tempfile.TemporaryDirectory() as td:
            pw = via_john(res, td)
    if not pw:
        pw = via_python(res)
    assert pw, "未破解出口令 (需要 rockyou, 见 ctf.py doctor)"
    with zipfile.ZipFile("leaked.zip") as z:
        data = z.read("flag.txt", pwd=pw.encode("latin-1")).decode("utf-8")
    for line in data.splitlines():
        if "flag{" in line:
            body = line.split("flag{", 1)[1].split("}")[0]
            print("flag{" + body + "}")
            break


if __name__ == "__main__":
    main()
