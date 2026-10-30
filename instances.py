# -*- coding: utf-8 -*-
"""
instances.py — 题目实例管理 (验证实例 + 服务实例)

「验证实例」: 复制 src/ 附件到 instances/verify/<name>/，在其中运行参考题解。
「服务实例」: 对带 server.py / oracle.py 的题目启动本地服务进程, 分配端口,
             供玩家用 nc / python socket / 浏览器手动交互。

打包成 exe 后没有独立 python 解释器, 所有脚本都通过
    <exe> --run-py <script> [args...]
由本程序自身充当解释器执行 (见 ctf.py 的入口分支)。
"""
import atexit
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import labenv

LAB = labenv.LAB
WLAB = labenv.WLAB
INST_ROOT = WLAB / "instances"

_live = {}          # name -> dict
_lock = threading.RLock()


def py_argv(script: Path, *args) -> list:
    """构造执行 Python 脚本的命令行 (兼容源码 / 打包两种运行方式)"""
    if labenv.is_frozen():
        return [sys.executable, "--run-py", str(script), *map(str, args)]
    return [sys.executable, str(script), *map(str, args)]


def copy_src(c, dest: Path) -> bool:
    """把题目附件复制到实例目录 (附 README)"""
    import json
    idx = json.loads((LAB / "challenges" / "index.json").read_text(encoding="utf-8"))
    meta = {x["name"]: x for x in idx["challenges"]}[c["name"]]
    src = LAB / "challenges" / meta["category"] / meta["name"] / "src"
    if not src.exists() or not any(src.iterdir()):
        return False
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest)
    files = sorted(p.name for p in dest.iterdir() if p.is_file())
    cat_cn = {
        "classical": "古典密码", "symmetric": "对称密码", "stream": "流密码与PRNG",
        "rsa": "RSA", "pubkey": "公钥与离散对数", "hash": "哈希", "lattice": "格密码",
        "cracking": "口令破解实战",
    }.get(meta["category"], meta["category"])
    (dest / "README.md").write_text(
        f"# {meta['name']}\n\n"
        f"- 分类: {cat_cn} · 难度: {meta['difficulty']} · {meta['points']} 分\n"
        f"- 考点: {meta['technique']}\n\n{meta['description']}\n\n"
        f"附件: {', '.join(files)}\n\n"
        f"flag 格式 flag{{...}} · 提示: python ctf.py hint {meta['name']} 1\n",
        encoding="utf-8")
    return True


def fresh_dir(base: Path) -> Path:
    """返回可用的目录 (旧实例目录被占用时自动换名, 避免 WinError 32)"""
    if not base.exists():
        return base
    try:
        shutil.rmtree(base)
        return base
    except OSError:
        pass
    for i in range(2, 50):
        alt = base.with_name(f"{base.name}-{i}")
        if not alt.exists():
            return alt
        try:
            shutil.rmtree(alt)
            return alt
        except OSError:
            continue
    return base.with_name(f"{base.name}-{int(time.time())}")


def verify_dir(name: str) -> Path:
    return INST_ROOT / "verify" / name


def server_script(c) -> Path | None:
    """网络服务脚本 (仅 server.py; oracle.py 是 stdin/stdout 工具, 不占端口)"""
    p = LAB / "challenges" / c["category"] / c["name"] / "src" / "server.py"
    return p if p.exists() else None


def oracle_script(c) -> Path | None:
    p = LAB / "challenges" / c["category"] / c["name"] / "src" / "oracle.py"
    return p if p.exists() else None


def run_hint(c) -> str | None:
    """oracle 类题目的本地运行命令 (打包/源码通用)"""
    op = oracle_script(c)
    if not op:
        return None
    inst = INST_ROOT / "server" / c["name"]
    script = inst / op.name
    if labenv.is_frozen():
        return f'"{sys.executable}" --run-py "{script}"'
    return f'python "{script}"'


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------ 服务实例
def start_server(c) -> dict:
    """启动题目服务, 返回 {ok, port, ready, instance, cmd, error}"""
    name = c["name"]
    if any(x["name"] == name for x in list_servers()):
        stop_server(name)          # 先停旧实例 (不能嵌套在锁内, 避免重入问题)
    script_src = server_script(c)
    if not script_src:
        return {"ok": False, "error": "该题没有 server.py / oracle.py"}
    inst = fresh_dir(INST_ROOT / "server" / name)
    if not copy_src(c, inst):
        return {"ok": False, "error": "附件未生成, 请先领取题目 (gen)"}
    script = inst / script_src.name
    port = free_port()
    cmd = py_argv(script, "--port", port)
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
               PYTHONUNBUFFERED="1")
    try:
        proc = subprocess.Popen(cmd, cwd=str(inst), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", env=env,
                                bufsize=1)
    except OSError as e:
        return {"ok": False, "error": f"启动失败: {e}"}

    ready, lines = None, []
    deadline = time.time() + 20
    # 读到 READY 行 (server.py 约定) 即认为就绪; oracle.py 无 READY 则等端口
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            line = line.rstrip("\n")
            lines.append(line)
            if line.startswith("READY"):
                ready = line
                break
        elif proc.poll() is not None:
            break
        else:
            time.sleep(0.05)
    if ready is None:
        # oracle.py 之类: 端口打开即算就绪
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    ready = f"(端口 {port} 已监听)"
                    break
            except OSError:
                time.sleep(0.1)
    if ready is None:
        out = "\n".join(lines)[-800:]
        try:
            proc.kill()
        except OSError:
            pass
        return {"ok": False, "error": f"服务未就绪\n{out}", "instance": str(inst)}

    threading.Thread(target=_drain, args=(proc,), daemon=True).start()
    rec = {"proc": proc, "port": port, "ready": ready, "instance": str(inst),
           "started": time.strftime("%H:%M:%S"), "script": script.name,
           "cmd": cmd, "name": name}
    with _lock:
        _live[name] = rec
    return {"ok": True, "port": port, "ready": ready, "instance": str(inst),
            "script": script.name, "cmd": _pretty_cmd(cmd),
            "first_lines": lines[:6]}


def _drain(proc):
    try:
        for _ in proc.stdout:
            pass
    except (OSError, ValueError):
        pass


def _pretty_cmd(cmd) -> str:
    parts = []
    for x in cmd:
        x = str(x)
        if re_like_path(x) and len(x) > 60:
            x = "…" + x[-46:]
        parts.append(f'"{x}"' if " " in x else x)
    return " ".join(parts)


def re_like_path(x: str) -> bool:
    return (":" in x and "\\" in x) or x.startswith("/")


def stop_server(name: str) -> dict:
    with _lock:
        rec = _live.pop(name, None)
    if not rec:
        return {"ok": False, "error": "没有正在运行的服务实例"}
    try:
        rec["proc"].terminate()
        try:
            rec["proc"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            rec["proc"].kill()
    except OSError:
        pass
    return {"ok": True}


def list_servers() -> list:
    with _lock:
        items = list(_live.values())
    return [{"name": r["name"], "port": r["port"], "ready": r["ready"],
             "instance": r["instance"], "started": r["started"],
             "script": r["script"], "alive": r["proc"].poll() is None}
            for r in items]


def stop_all():
    for name in list(_live.keys()):
        stop_server(name)


atexit.register(stop_all)


# ------------------------------------------------------------------ 验证实例
def run_reference_solution(c, keep: bool = False, timeout: int | None = None) -> dict:
    """
    在实例目录中运行参考题解, 返回可展示的完整过程:
      steps[] / stdout / stderr / flag / expected / pass / seconds / instance / kept
    keep=True 时不删除实例, 便于玩家查看生成的附件与运行现场。
    """
    name = c["name"]
    solve = LAB / "challenges" / c["category"] / name / "solution" / "solve.py"
    result = {"ok": False, "name": name, "steps": [], "stdout": "", "stderr": "",
              "flag": None, "expected": c.get("flag"), "pass": False,
              "seconds": 0.0, "instance": None, "kept": bool(keep)}

    def step(title, detail="", status="info"):
        result["steps"].append({"n": len(result["steps"]) + 1, "title": title,
                                "detail": str(detail), "status": status})

    if not solve.exists():
        step("查找参考题解", f"未找到 {solve.relative_to(LAB)}", "fail")
        return result

    inst = fresh_dir(verify_dir(name)) if keep else (INST_ROOT / "tmp" / f"{name}-{os.getpid()}")
    if not copy_src(c, inst):
        step("创建实例", "附件未生成 —— 请先点击「领取题目」", "fail")
        return result
    result["instance"] = str(inst)
    files = sorted(p.name for p in inst.iterdir() if p.is_file())
    step("创建实例目录", f"{inst}\n复制附件 {len(files)} 个: {', '.join(files) or '(无)'}", "ok")

    cmd = py_argv(solve)
    step("启动参考题解", _pretty_cmd(cmd), "ok")
    t0 = time.time()
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    out = err = ""
    try:
        r = subprocess.run(cmd, cwd=str(inst), capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=timeout or c.get("timeout", 240), env=env)
        result["seconds"] = round(time.time() - t0, 2)
        out, err = r.stdout or "", r.stderr or ""
        result["stdout"], result["stderr"] = out, err
        step("运行完成", f"退出码 {r.returncode} · 耗时 {result['seconds']}s",
             "ok" if r.returncode == 0 else "fail")
    except subprocess.TimeoutExpired:
        result["seconds"] = round(time.time() - t0, 2)
        step("运行超时", f"超过 {timeout or c.get('timeout', 240)}s", "fail")
        result["stderr"] = f"timeout after {result['seconds']}s"
        return _finish(result, inst, keep, c)

    m = None
    for mm in re_find_flags(out + "\n" + err):
        m = mm
    result["flag"] = m
    if m:
        ok = (m == c["flag"])
        step("提取 flag", m, "ok" if ok else "fail")
        step("与标准答案比对", "一致 ✓" if ok else f"不一致 (期望 {c['flag']})",
             "ok" if ok else "fail")
        result["pass"] = ok
    else:
        step("提取 flag", "stdout/stderr 中没有 flag{...}", "fail")
    result["ok"] = True
    return _finish(result, inst, keep, c)


def _finish(result, inst: Path, keep: bool, c) -> dict:
    if keep:
        result["kept"] = True
        result["steps"].append({"n": len(result["steps"]) + 1, "title": "保留实例",
                                "detail": f"实例已保留, 可打开查看: {inst}", "status": "info"})
    else:
        shutil.rmtree(inst, ignore_errors=True)
        result["steps"].append({"n": len(result["steps"]) + 1, "title": "清理实例",
                                "detail": "临时实例已删除 (勾选「保留实例」可查看现场)",
                                "status": "info"})
    return result


def re_find_flags(text):
    import re
    return [m.group(0) for m in re.finditer(r"flag\{[^}\s]*\}", text)]


def cleanup_tmp():
    shutil.rmtree(INST_ROOT / "tmp", ignore_errors=True)
