"""题解：shadow-crack
## 漏洞点
/etc/shadow 里的 $6$ (sha512crypt) 虽是慢哈希 (默认 5000 轮)，但口令本身来自
常见字典——慢哈希防不住弱口令，只是把穷举时间乘上 5000。John the Ripper 的
高度优化实现 (SIMD + 多线程) 依然能在分钟级吃掉千万级字典。

## 利用思路
1. (可选) unshadow passwd.txt shadow.txt 合并成 john 输入格式。
2. john --wordlist=rockyou shadow.txt —— john 自动识别 $6$ 并并行破解。
3. john --show 读回全部口令；deploy 的口令用于解密 vault.txt：
   flag = xor(hex→bytes, sha256("vault:" + deploy口令)) 逐字节异或。
4. 本题纯 Python 不可行 (sha512crypt 单条 ~25ms)，需要 John (或 hashcat)。

## 关键代码
import hashlib
ks = hashlib.sha256(b"vault:" + deploy_pw).digest() * 2
flag = bytes(a ^ b for a, b in zip(bytes.fromhex(vault_hex), ks))

## 防御建议
- /etc/shadow 权限 000，备份系统排除敏感文件并加密存储。
- 口令策略: 长度 ≥ 12 且与泄露字典比对; 高权限账户强制 MFA。
- 部署 fail2ban/auditd, 对 su/sudo 失败峰值告警; 定期用 john 自查口令强度。
"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))
import resources as RES  # noqa: E402


def via_john(res, workdir):
    john = res["john"]["exe"]
    hashf = Path(workdir) / "shadow.hash"
    shadow_text = Path("shadow.txt").read_text(encoding="utf-8")
    hashf.write_text(shadow_text, encoding="utf-8")
    pot = Path(workdir) / "ctf.pot"
    r = subprocess.run([john, f"--wordlist={res['rockyou']['path']}", f"--pot={pot}", str(hashf)],
                       capture_output=True, text=True, timeout=900)
    # pot 行格式 <$6$salt$hash>:<password>; 用哈希回查用户名
    user_of_hash = {}
    for line in shadow_text.splitlines():
        if line.startswith("$") or ":$6$" in line:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].startswith("$6$"):
                user_of_hash[parts[1]] = parts[0]
    found = {}
    if pot.exists():
        for ln in pot.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in ln:
                continue
            h, _, pw_ = ln.rpartition(":")
            u = user_of_hash.get(h)
            if u and pw_:
                found[u] = pw_
    return found or None


def main():
    res = RES.get_resources()
    assert res.get("john"), "本题需要 John the Ripper (ctf.py doctor 查看); sha512crypt 无法用纯 Python 在合理时间内枚举"
    pwds = None
    with tempfile.TemporaryDirectory() as td:
        pwds = via_john(res, td)
    assert pwds and pwds.get("deploy"), "未能破解 deploy 口令"
    vault_hex = [l.strip() for l in Path("vault.txt").read_text(encoding="utf-8").splitlines()
                 if l.strip() and all(c in "0123456789abcdef" for c in l.strip())][-1]
    ks = hashlib.sha256(b"vault:" + pwds["deploy"].encode("latin-1")).digest() * 2
    flag = bytes(a ^ b for a, b in zip(bytes.fromhex(vault_hex.strip()), ks))
    print(flag.decode())


if __name__ == "__main__":
    main()
