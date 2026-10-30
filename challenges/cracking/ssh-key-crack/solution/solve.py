"""题解：ssh-key-crack
## 漏洞点
私钥文件使用传统 PEM 加密 (Proc-Type: 4,ENCRYPTED)。这类格式的口令 KDF
只做了极少的拉伸，口令验证速率极高——John the Ripper 配合 rockyou 字典
几分钟内就能穷举千万级弱口令。私钥一旦泄露，其保护的一切凭据随之失守。

## 利用思路
1. ssh2john.py id_rsa > hash.txt (john jumbo 自带该转换脚本)。
2. john --wordlist=rockyou hash.txt 爆破口令 (本题口令在 rockyou 前 10 万行)。
3. openssl rsa -in id_rsa -passin pass:<口令> 解出明文私钥。
4. RSA.import_key 导入私钥, RSA-OAEP 解密 challenge.txt (hex) 得 flag。

## 关键代码
subprocess.run(["openssl", "rsa", "-in", "id_rsa", "-passin", "pass:" + pw,
                "-out", "plain.pem"])
priv = RSA.import_key(open("plain.pem").read())
flag = PKCS1_OAEP.new(priv).decrypt(bytes.fromhex(open("challenge.txt").read()))

## 防御建议
- 生成密钥用 OpenSSH 新格式 (bcrypt KDF, aes256-ctr), 口令高强度不重用。
- 私钥不落盘共享目录; 用 ssh-agent 与证书 (SSH CA) 替代长期私钥分发。
- 对跳板机 authorized_keys 加 from=/expiry-time 限制, 私钥泄露立即吊销。
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))
import resources as RES  # noqa: E402

from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Cipher import PKCS1_OAEP  # noqa: E402


def decrypt_pem(pem_path: Path, pw: str) -> str:
    r = subprocess.run(["openssl", "rsa", "-in", str(pem_path).replace("\\", "/"),
                        "-passin", "pass:" + pw],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and ("BEGIN PRIVATE KEY" in r.stdout
                                  or "BEGIN RSA PRIVATE KEY" in r.stdout), "口令验证失败"
    return r.stdout


def via_john(res, workdir):
    home = Path(res["john"]["home"])
    s2j = home / "ssh2john.py"
    hashf = Path(workdir) / "ssh.hash"
    # ssh2john.py (JtR 1.9 jumbo) 使用的 base64.decodestring 在 Python 3.9+ 已移除,
    # 打个兼容补丁再运行 (shim 脚本)
    shim = Path(workdir) / "s2j_shim.py"
    shim.write_text(
        "import base64, sys, runpy\n"
        "if not hasattr(base64, 'decodestring'):\n"
        "    base64.decodestring = base64.decodebytes\n"
        "sys.argv = ['ssh2john.py'] + sys.argv[1:]\n"
        "runpy.run_path(sys.argv[0].replace('s2j_shim.py', '') if False else %r, run_name='__main__')\n"
        % str(s2j), encoding="utf-8")
    r = subprocess.run([sys.executable, str(shim), "id_rsa"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "$sshng$" in (r.stdout or ""), \
        f"ssh2john 失败: {r.stderr[-300:]}"
    hashf.write_text(r.stdout.strip(), encoding="utf-8")
    pot = Path(workdir) / "ctf.pot"
    john = res["john"]["exe"]
    subprocess.run([john, f"--wordlist={res['rockyou']['path']}", f"--pot={pot}", str(hashf)],
                   capture_output=True, text=True, timeout=900)
    # 解析 pot 文件 (行格式 <hash>:<password>, hash 内不含冒号)
    if pot.exists():
        for ln in pot.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in ln:
                pw_ = ln.rsplit(":", 1)[1]
                if pw_:
                    return pw_
    return None


def main():
    res = RES.get_resources()
    assert res.get("john") and res.get("rockyou"), \
        "本题需要 John the Ripper + rockyou (python ctf.py doctor 查看)"
    pw = None
    with tempfile.TemporaryDirectory() as td:
        pw = via_john(res, td)
    assert pw, "未破解出口令"
    plain = decrypt_pem(Path("id_rsa"), pw)
    priv = RSA.import_key(plain)
    ct = bytes.fromhex(Path("challenge.txt").read_text().strip())
    flag = PKCS1_OAEP.new(priv).decrypt(ct)
    print(flag.decode())


if __name__ == "__main__":
    main()
