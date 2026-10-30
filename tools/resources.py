# -*- coding: utf-8 -*-
"""
resources.py — 外部安全工具资源探测 (John the Ripper / rockyou / hashcat / 7-Zip ...)

供 ctf.py doctor、cracking 类出题与解题脚本使用:
    from resources import get_resources, scan_resources, save_cache, load_cache

发现结果缓存到 <LAB>/lib/resources.json。扫描范围: 磁盘根浅层目录 (默认 D:\\ C:\\),
可用环境变量 CTF_RES_ROOTS 覆盖 (分号分隔)。
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
try:                                   # 打包后缓存应落在可写目录
    import labenv
    _CACHE_ROOT = labenv.WLAB
except Exception:
    _CACHE_ROOT = LAB
CACHE = _CACHE_ROOT / "lib" / "resources.json"
CACHE.parent.mkdir(parents=True, exist_ok=True)


def _roots():
    env = os.environ.get("CTF_RES_ROOTS")
    if env:
        return [p for p in (s.strip() for s in env.split(";")) if p and Path(p).exists()]
    roots = []
    for drv in ("D", "C", "E"):
        p = Path(f"{drv}:\\")
        if p.exists():
            roots.append(p)
    return roots


def _walk_shallow(root, max_depth=3):
    """浅层遍历目录名 (不深入大文件夹)"""
    base = str(root)
    def walk(dirpath, depth):
        try:
            entries = list(os.scandir(dirpath))
        except OSError:
            return
        for e in entries:
            if e.is_dir():
                yield e.path
                if depth < max_depth:
                    yield from walk(e.path, depth + 1)
    yield from walk(base, 0)


def _norm(name):
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _find_dir(root, *needles):
    """在 root 浅层目录里找名字含全部 needles 的目录"""
    hits = []
    for d in _walk_shallow(root, 2):
        n = _norm(os.path.basename(d))
        if all(_norm(x) in n for x in needles):
            hits.append(d)
    return hits


def _find_file_shallow(root, name_exact, max_depth=3):
    for d in _walk_shallow(root, max_depth):
        try:
            entries = os.scandir(d)
        except OSError:
            continue
        for e in entries:
            if e.is_file() and e.name.lower() == name_exact:
                return e.path
    return None


def _john_version(john_exe):
    try:
        r = subprocess.run([str(john_exe)], capture_output=True, text=True,
                           timeout=15, errors="replace")
        m = re.search(r"John the Ripper (?:v|one-time-password cracker, version )?([\d.\w\-]+)",
                      (r.stdout or "") + (r.stderr or ""))
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def scan_resources():
    """扫描外部资源, 返回资源字典"""
    res = {
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "roots": [str(r) for r in _roots()],
        "john": None,
        "rockyou": None,
        "hashcat": None,
        "sevenzip": None,
        "wordlists": [],
    }
    for root in _roots():
        if res["john"] and res["rockyou"] and res["hashcat"]:
            break
        # John the Ripper
        if not res["john"]:
            for d in _find_dir(root, "john", "ripper"):
                # 命中目录或其下一层 (版本子目录) 里找 run/john.exe
                cand_dirs = [Path(d)] + [Path(p) for p in _walk_shallow(d, 1)]
                for base in cand_dirs:
                    run = base / "run"
                    for exe in (run / "john.exe", run / "john", base / "john.exe"):
                        if exe.exists():
                            res["john"] = {"exe": str(exe), "home": str(exe.parent),
                                           "version": _john_version(exe)}
                            break
                    if res["john"]:
                        break
                if res["john"]:
                    break
        # rockyou.txt / rockyou.txt.gz
        if not res["rockyou"]:
            for d in _walk_shallow(root, 2):
                p = Path(d) / "rockyou.txt"
                if p.exists():
                    res["rockyou"] = {"path": str(p), "gz": False}
                    break
                p2 = Path(d) / "rockyou.txt.gz"
                if p2.exists() and p2.stat().st_size > 1_000_000:
                    res["rockyou"] = {"path": str(p2), "gz": True}
                    break
        # hashcat
        if not res["hashcat"]:
            for d in _find_dir(root, "hashcat"):
                cand = Path(d) / "hashcat.exe"
                if cand.exists():
                    res["hashcat"] = {"exe": str(cand), "home": str(Path(cand).parent)}
                    break
                if (Path(d) / "hashcat").exists():
                    res["hashcat"] = {"exe": str(Path(d) / "hashcat"), "home": d}
                    break
    # 7-Zip: 常见安装位置 + PATH
    for cand in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(cand).exists():
            res["sevenzip"] = {"exe": cand}
            break
    else:
        from shutil import which
        w = which("7z")
        if w:
            res["sevenzip"] = {"exe": w}
    # rockyou 行数
    if res["rockyou"]:
        try:
            if res["rockyou"]["gz"]:
                import gzip
                with gzip.open(res["rockyou"]["path"], "rb") as f:
                    res["rockyou"]["lines"] = sum(1 for _ in f)
            else:
                with open(res["rockyou"]["path"], "rb") as f:
                    res["rockyou"]["lines"] = sum(1 for _ in f)
        except OSError:
            res["rockyou"]["lines"] = None
    return res


def save_cache(res):
    CACHE.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")


def load_cache():
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def get_resources(rescan=False):
    res = None if rescan else load_cache()
    if res is None:
        res = scan_resources()
        save_cache(res)
    return res


def rockyou_iter(res, limit=None):
    """迭代 rockyou 口令 (bytes, 去 \n). 支持 gz."""
    info = res.get("rockyou") if res else None
    if not info:
        return
    path = info["path"]
    n = 0
    if info.get("gz"):
        import gzip
        f = gzip.open(path, "rb")
    else:
        f = open(path, "rb")
    with f:
        for line in f:
            w = line.rstrip(b"\r\n")
            if w:
                yield w
                n += 1
                if limit and n >= limit:
                    return


def rockyou_line(res, lineno):
    """返回 rockyou 的第 lineno 行 (1-based) 口令 bytes; 越界返回 None"""
    if lineno < 1:
        return None
    for i, w in enumerate(rockyou_iter(res), 1):
        if i == lineno:
            return w
    return None


if __name__ == "__main__":
    r = scan_resources()
    save_cache(r)
    for k in ("john", "rockyou", "hashcat", "sevenzip"):
        print(f"{k}: {r[k]}")
