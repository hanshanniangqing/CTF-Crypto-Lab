"""题解：ntlm-crack
## 漏洞点
本地账户使用弱口令，且 NTLM 哈希（MD4(UTF-16LE(password))，无盐）被转储。
无盐意味着同一口令的哈希全局相同——拿字典一跑就现形。这正是 ransomware
团伙拿到 secretsdump 输出后第一件事就是做的事。

## 利用思路
1. 从 ntlm_dump.txt 提取 6 条 (user, ntlm-hash)。
2. 首选 John the Ripper: john --format=NT --wordlist=rockyou --pot=临时pot。
3. 无 John 时纯 Python 枚举: NTLM = MD4(UTF-16LE(pw))，rockyou 每行的 MD4
   与目标比对（MD4 极快，百万级 < 1 分钟）。
4. Administrator 账户的口令即 flag body。

## 关键代码
h = MD4.new(); h.update(pw.encode("utf-16-le"))
if h.hexdigest().upper() == target: hit(pw)

## 防御建议
- 强制口令长度与复杂性策略 + 定期与泄露口令库比对（禁止 rockyou 类口令）。
- 启用 NTLMv2/LM 禁用，迁移 Kerberos；对高价值账户开启 Credential Guard。
- 域内部署 honey account，任何对其 NTLM 的使用立即告警。
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))
import ctfk  # noqa: E402
import resources as RES  # noqa: E402

from Crypto.Hash import MD4  # noqa: E402


def ntlm(pw: bytes) -> str:
    h = MD4.new()
    h.update(pw.decode("latin-1").encode("utf-16-le"))
    return h.hexdigest().upper()


def via_john(targets, res, workdir):
    john = res["john"]["exe"]
    hashf = Path(workdir) / "ntlm.hash"
    hashf.write_text("\n".join(targets.values()), encoding="utf-8")
    pot = Path(workdir) / "ctf.pot"
    r = subprocess.run([john, "--format=NT", f"--wordlist={res['rockyou']['path']}",
                        f"--pot={pot}", str(hashf)],
                       capture_output=True, text=True, timeout=600)
    if r.returncode not in (0, 1):
        return None
    out = subprocess.run([john, "--show", f"--pot={pot}", str(hashf)],
                         capture_output=True, text=True, timeout=60).stdout
    found = {}
    for line in out.splitlines():
        if ":" in line and not line.startswith(("0 ", "1 ")):
            h, _, pw = line.rpartition(":")
            if h in targets:
                found[h] = pw
    return found or None


def via_python(targets, res):
    # 纯 Python: MD4 极快, 枚举 rockyou 前 6 万行足够 (口令都在前 5 万)
    found = {}
    want = set(targets)
    for w in RES.rockyou_iter(res, limit=60000):
        h = ntlm(w)
        if h in want and h not in found:
            found[h] = w.decode("latin-1")
    if len(found) < len(want):
        for w in b"123456 password qwerty abc123 letmein trustno1 iloveyou monkey".split():
            h = ntlm(w)
            if h in want and h not in found:
                found[h] = w.decode()
    return found or None


def main():
    targets = {}
    for line in open("ntlm_dump.txt", encoding="utf-8"):
        line = line.strip()
        if line.startswith("#") or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) >= 4 and re.fullmatch(r"[0-9A-Fa-f]{32}", parts[3]):
            targets[parts[3].upper()] = parts[0]
    assert len(targets) >= 6, "附件解析失败"
    res = RES.get_resources()
    found = None
    if res.get("john") and res.get("rockyou"):
        with tempfile.TemporaryDirectory() as td:
            found = via_john(targets, res, td)
    if not found:
        found = via_python(targets, res)
    assert found and found.get([k for k, v in targets.items() if v == "Administrator"][0]), \
        "字典未能覆盖全部口令 (需要 rockyou, 见 ctf.py doctor)"
    admin_pw = found[[k for k, v in targets.items() if v == "Administrator"][0]]
    print("flag{" + admin_pw + "}")


if __name__ == "__main__":
    main()
