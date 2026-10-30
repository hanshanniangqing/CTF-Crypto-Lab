# -*- coding: utf-8 -*-
"""cracking 分类出题脚本 (4 题): ntlm-crack, zip-crack, ssh-key-crack, shadow-crack

依赖外部资源 (John the Ripper + rockyou, 探测见 tools/resources.py):
  * gen 侧: rockyou 取真实弱口令; zip 题用 7-Zip 生成 ZipCrypto 压缩包;
            ssh 题用系统 OpenSSH 生成带口令 PEM 私钥。
  * 缺少资源时自动降级: 口令改用内置迷你词表 (迷你词表含于本文件)。
"""
import hashlib
import struct
import subprocess
import sys
import tempfile
from build_common import *
import resources as RES

from Crypto.Hash import MD4  # noqa: E402  (pycryptodome)

# 与 rockyou 风格一致的迷你词表 (无外部字典时的确定性降级口令池)
MINI_PWDS = [
    b"123456", b"password", b"12345678", b"qwerty", b"abc123", b"monkey",
    b"letmein", b"dragon", b"111111", b"baseball", b"iloveyou", b"trustno1",
    b"sunshine", b"master", b"shadow", b"superman", b"michael", b"football",
    b"password1", b"batman", b"freedom", b"whatever", b"qazwsx", b"google",
]


def pick_password(name, idx, max_line):
    """按确定性方式从 rockyou 第 N 行取口令; 无 rockyou 时用迷你词表"""
    rng = rng_for(name)
    res = RES.get_resources()
    if res.get("rockyou") and res["rockyou"].get("lines", 0) > max_line:
        n = rng.randint(2, max_line)
        pw = RES.rockyou_line(res, n)
        src = f"rockyou 第 {n} 行"
        if pw is None:
            pw = MINI_PWDS[idx % len(MINI_PWDS)]
            src = "mini"
    else:
        pw = MINI_PWDS[(idx * 7 + 3) % len(MINI_PWDS)]
        src = "mini"
    return pw, src


def ntlm_hash(pw: bytes) -> str:
    h = MD4.new()
    h.update(pw.decode("latin-1").encode("utf-16-le"))
    return h.hexdigest().upper()


# ---------------------------------------------------------------- ntlm-crack
@register("ntlm-crack")
def gen_ntlm_crack(ch):
    flag = ch["flag"]
    admin_pw = flag[len("flag{"):-1].encode()   # flag{trustno1} -> trustno1
    rng = rng_for("ntlm-crack")
    users = ["sql-svc", "backup-agent", "helpdesk01", "git-runner", "jira-bot", "Administrator"]
    entries = []
    used = {admin_pw}
    for i, u in enumerate(users):
        if u == "Administrator":
            pw = admin_pw
        else:
            pw, _src = pick_password("ntlm-crack", i, 50000)
            tries = 0
            while pw in used and tries < 50:
                rng2 = rng_for(f"ntlm-crack-extra{i}-{tries}")
                pw, _src = pick_password(f"ntlm-crack-{i}-{tries}", 0, 50000)
                tries += 1
        used.add(pw)
        entries.append((u, pw, ntlm_hash(pw)))
        verify("ntlm-crack", ntlm_hash(pw) == entries[-1][2], f"NTLM 自检失败 {u}")
    txt = (
        "# impacket-secretsdump.py 摘录 (本机 SAM)\n"
        "# format: user:rid:lm-hash:ntlm-hash:::\n"
    )
    for rid, (u, pw, h) in enumerate(entries, 1000):
        txt += f"{u}:{rid}:aad3b435b51404eeaad3b435b51404ee:{h}:::\n"
    write_src("ntlm-crack", "ntlm_dump.txt", txt)
    write_src("ntlm-crack", "README.txt",
              "内网渗透时从域控转储的本地账户 NTLM 哈希。\n"
              "口令全部属于常见弱口令字典 (rockyou)。flag = Administrator 账户的口令,\n"
              "套上 flag{} 即为答案。\n")
    # 自检: admin 口令必须真在 rockyou 里 (保证可被字典破解)
    res = RES.get_resources()
    if res.get("rockyou"):
        found = any(w == admin_pw for w in RES.rockyou_iter(res, limit=100000))
        verify("ntlm-crack", found, "admin 口令必须存在于 rockyou 前 10 万行")
    verify("ntlm-crack", len({p for _, p, _ in entries}) == 6, "口令必须互不相同")


# ---------------------------------------------------------------- zip-crack
@register("zip-crack")
def gen_zip_crack(ch):
    flag = ch["flag"]
    res = RES.get_resources()
    pw, src = pick_password("zip-crack", 0, 200000)
    with tempfile.TemporaryDirectory() as td:
        td = tempfile.mkdtemp(prefix="ctfzip_")
        try:
            (Path(td) / "flag.txt").write_text(
                "recovered archive\nthe flag is: " + flag + "\n", encoding="utf-8")
            (Path(td) / "meeting_notes.txt").write_text(
                "2026-10-20 weekly sync\n- rotate prod keys\n- audit vpn logs\n- bring donuts\n",
                encoding="utf-8")
            out = Path(td) / "leaked.zip"
            sz = (res.get("sevenzip") or {}).get("exe")
            if not sz:
                raise RuntimeError("需要 7-Zip 生成加密压缩包 (ctf.py doctor)")
            r = subprocess.run([sz, "a", "-tzip", "-mem=ZipCrypto", f"-p{pw.decode('latin-1')}",
                                str(out), "flag.txt", "meeting_notes.txt"],
                               cwd=td, capture_output=True, text=True, timeout=60)
            verify("zip-crack", r.returncode == 0, f"7z 失败: {r.stderr[:200]}")
            write_src("zip-crack", "leaked.zip", out.read_bytes())
        finally:
            import shutil as _sh
            _sh.rmtree(td, ignore_errors=True)
    # 自检: 标准库 zipfile 能用该口令解出 flag
    import zipfile
    zpath = ch_dir("zip-crack") / "src" / "leaked.zip"
    with zipfile.ZipFile(zpath) as z:
        data = z.read("flag.txt", pwd=pw).decode("utf-8")
    verify("zip-crack", flag in data, "zip 口令自检失败")
    write_src("zip-crack", "README.txt",
              "从员工邮箱附件里抢救出来的加密压缩包 (ZipCrypto 传统加密)。\n"
              f"口令来源: {src}。破解出压缩包内 flag.txt 的内容。\n")


# ---------------------------------------------------------------- ssh-key-crack
@register("ssh-key-crack")
def gen_ssh_key_crack(ch):
    flag = ch["flag"]
    res = RES.get_resources()
    pw, src = pick_password("ssh-key-crack", 1, 100000)
    td = tempfile.mkdtemp(prefix="ctfssh_")
    try:
        keyf = Path(td) / "id_rsa"
        cmd = ["ssh-keygen", "-t", "rsa", "-b", "2048", "-m", "PEM", "-q",
               "-N", pw.decode("latin-1"), "-C", flag, "-f", str(keyf)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            ssh = r"C:\Windows\System32\OpenSSH\ssh-keygen.exe"
            r = subprocess.run([ssh] + cmd[1:], capture_output=True, text=True, timeout=120)
        verify("ssh-key-crack", r.returncode == 0, f"ssh-keygen 失败: {r.stderr[:300]}")
        pem = keyf.read_text(encoding="utf-8")
        pub_text = keyf.with_suffix(".pub").read_text(encoding="utf-8")
        write_src("ssh-key-crack", "id_rsa", pem)
        # 自检 1: PEM 应为传统加密格式; openssl 口令可解出私钥
        verify("ssh-key-crack", "Proc-Type: 4,ENCRYPTED" in pem, "应为传统 PEM 加密私钥")
        verify("ssh-key-crack", "DEK-Info: AES-128-CBC" in pem or "DEK-Info: DES-EDE3-CBC" in pem,
               "应为传统 PEM 加密 KDF (AES-128-CBC / DES-EDE3-CBC)")
        plain_pem_text = subprocess.run(
            ["openssl", "rsa", "-in", keyf.as_posix(), "-passin", "pass:" + pw.decode("latin-1")],
            capture_output=True, text=True, timeout=60).stdout
        verify("ssh-key-crack", ("BEGIN PRIVATE KEY" in plain_pem_text
                                 or "BEGIN RSA PRIVATE KEY" in plain_pem_text)
               and "ENCRYPTED" not in plain_pem_text, "openssl 解密私钥失败")
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)
    # 生成挑战文件: 用对应公钥 OAEP 加密 flag —— 破解口令恢复私钥后才能解开
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    pub = RSA.import_key(pub_text)
    ct = PKCS1_OAEP.new(pub).encrypt(flag.encode())
    write_src("ssh-key-crack", "challenge.txt", ct.hex() + "\n")
    # 自检 2: 解出的明文私钥能解密挑战 == flag
    priv = RSA.import_key(plain_pem_text)
    back = PKCS1_OAEP.new(priv).decrypt(ct)
    verify("ssh-key-crack", back.decode() == flag, "挑战文件加解密自检失败")
    write_src("ssh-key-crack", "README.txt",
              "离职运维留在跳板机上的加密 SSH 私钥 (传统 PEM, AES-128-CBC)。\n"
              f"口令来源: {src}。破解口令恢复私钥, 用它解密 challenge.txt:\n"
              "challenge.txt = hex(RSA-OAEP 公钥加密的 flag)。\n"
              "恢复私钥: openssl rsa -in id_rsa -passin pass:<口令> (或 john 破出后任意工具)。\n")


# ---------------------------------------------------------------- shadow-crack
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_S512_ORDER = [
    [0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4], [47, 5, 26],
    [6, 27, 48], [28, 49, 7], [50, 8, 29], [9, 30, 51], [31, 52, 10], [53, 11, 32],
    [12, 54, 33], [55, 13, 34], [14, 35, 56], [36, 57, 15], [58, 16, 37], [17, 38, 59],
    [39, 60, 18], [61, 19, 40], [20, 41, 62],
]


def sha512_crypt(password: bytes, salt: bytes, rounds: int = 5000) -> str:
    """sha512-crypt ($6$) —— 经 openssl passwd -6 生成 (权威实现)."""
    r = subprocess.run(["openssl", "passwd", "-6", "-salt", salt.decode(),
                        password.decode("latin-1")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("需要 openssl (Git Bash 自带) 生成 $6$ 哈希: " + r.stderr[:200])
    return r.stdout.strip()


@register("shadow-crack")
def gen_shadow_crack(ch):
    flag = ch["flag"]
    users = [("root", 0), ("deploy", 1001), ("svc-legacy", 1002)]
    lines = []
    deploy_pw = None
    for i, (u, uid) in enumerate(users):
        pw, src = pick_password("shadow-crack", i, 80000)
        if u == "deploy":
            deploy_pw = pw
        salt = rng_for("shadow-crack" + u).randrange(10**17, 10**18)
        salt_hex = b"%016x" % salt
        h = sha512_crypt(pw, salt_hex)
        lines.append((u, h))
        # 自检: 与 openssl passwd -6 对照 (若可用)
        try:
            r = subprocess.run(["openssl", "passwd", "-6", "-salt", salt_hex.decode(),
                                pw.decode("latin-1")], capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                verify("shadow-crack", r.stdout.strip() == h, f"sha512crypt 对照失败 ({u})")
        except FileNotFoundError:
            verify("shadow-crack", h.startswith(f"$6${salt_hex.decode()}$"), "哈希格式异常")
    shadow = "\n".join(
        f"{u}:{h}:19700:0:99999:7:::" for u, h in lines)
    passwd = "\n".join(
        f"{u}:x:{1000 + i}:{1000 + i}::/home/{u}:/bin/bash" for i, (u, _) in enumerate(lines))
    write_src("shadow-crack", "shadow.txt", shadow + "\n")
    write_src("shadow-crack", "passwd.txt", passwd + "\n")
    # vault: 用 deploy 口令派生密钥异或加密 flag —— 必须破解才能拿到答案
    ks = hashlib.sha256(b"vault:" + deploy_pw).digest() * 2
    vault = bytes(a ^ b for a, b in zip(flag.encode(), ks)).hex()
    write_src("shadow-crack", "vault.txt",
              "deploy 用户的私人备忘 (AES 前身方案, 密钥 = sha256('vault:' + 口令)):\n"
              f"{vault}\n")
    write_src("shadow-crack", "README.txt",
              "一次失误的备份把 /etc/shadow 带了出来 (sha512crypt, $6$)。\n"
              "3 个可登录账户的口令都来自常见字典。破解 deploy 的口令后解密 vault.txt:\n"
              "flag = xor(vault_hex, sha256('vault:' + deploy口令)) 逐字节异或。\n")
    # 自检
    back = bytes(a ^ b for a, b in zip(bytes.fromhex(vault), ks))
    verify("shadow-crack", back.decode() == flag, "vault 加解密自检失败")


if __name__ == "__main__":
    run_builders(BUILDERS)
