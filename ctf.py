# -*- coding: utf-8 -*-
"""
ctf.py — CTF Crypto Lab 平台 CLI (v2: 富文本 / 交互菜单 / Web 控制台 / 外部资源)

用法:
  python ctf.py                 交互式模式 (推荐)
  python ctf.py ui              同上
  python ctf.py list            题目一览 (富文本表格)
  python ctf.py info <name>     题目详情
  python ctf.py hint <name> [n] 逐步提示
  python ctf.py flag <name>     查看答案 (不计入完成)
  python ctf.py submit <name> [--flag 'flag{...}']   提交 flag 判题 (唯一记完成的方式)
  python ctf.py progress        做题进度 (分类统计 / 已完成列表)
  python ctf.py gen <name|all>  生成玩家文件到 dist/
  python ctf.py check <name|all> [--verbose]   运行解题脚本验证 (带进度条)
  python ctf.py writeup <name>  查看题解
  python ctf.py regen <name|all> 重新出题
  python ctf.py doctor          探测 John the Ripper / rockyou / hashcat 等外部资源
  python ctf.py serve [--port N]  启动 Web 控制台 (浏览器图形界面)
  python ctf.py --plain         关闭彩色输出
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

import labenv  # noqa: E402  (源码/打包通用的路径定位)

LAB = labenv.LAB          # 只读资源根
WLAB = labenv.WLAB        # 可写根 (dist / instances / 缓存)
sys.path.insert(0, str(LAB / "lib"))
sys.path.insert(0, str(LAB / "tools"))
sys.path.insert(0, str(LAB))

import ui as U  # noqa: E402
from ui import UI  # noqa: E402

INDEX_PATH = LAB / "challenges" / "index.json"

VERSION = "CTF Crypto Lab v3.2"

CATEGORY_ORDER = ["classical", "symmetric", "stream", "rsa", "pubkey", "hash", "lattice", "cracking"]
CATEGORY_CN = {
    "classical": "古典密码",
    "symmetric": "对称密码",
    "stream": "流密码与PRNG",
    "rsa": "RSA",
    "pubkey": "公钥与离散对数",
    "hash": "哈希",
    "lattice": "格密码",
    "cracking": "口令破解实战",
}


def load_index():
    with open(INDEX_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {c["name"]: c for c in data["challenges"]}, data


def resolve_targets(names):
    index, _ = load_index()
    if names == ["all"]:
        return list(index.values())
    out = []
    for nm in names:
        if nm not in index:
            U.err(f"未知题目: {nm}   (python ctf.py list 查看全部)")
            sys.exit(1)
        out.append(index[nm])
    return out


# ------------------------------------------------------------------ commands

def cmd_list(args):
    index, _ = load_index()
    the = args.ui_obj
    for cat in CATEGORY_ORDER:
        chs = [c for c in index.values() if c["category"] == cat]
        if not chs:
            continue
        rows = []
        for c in sorted(chs, key=lambda x: x["points"]):
            src = (LAB / "challenges" / c["category"] / c["name"] / "src").exists()
            sol = (LAB / "challenges" / c["category"] / c["name"] / "solution" / "solve.py").exists()
            rows.append([c["name"], c["difficulty"], str(c["points"]), c["technique"],
                         "✓" if src else "未生成", "✓" if sol else "—"])
        the.table(f"{CATEGORY_CN[cat]} ({cat})", ["题目", "难度", "分值", "考点", "材料", "题解"], rows)
    n = len(index)
    the.rule()
    the.console.print(f"  [bold]共 {n} 题[/bold]  ·  [cyan]python ctf.py gen all[/cyan] 领取全部  "
                      f"·  [cyan]python ctf.py submit <题目>[/cyan] 提交 flag  "
                      f"·  [cyan]python ctf.py serve[/cyan] 图形界面")


def cmd_info(args):
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    the = args.ui_obj
    the.panel(
        f"[bold]{c['description']}[/bold]\n\n"
        f"[dim]分类[/dim] {CATEGORY_CN[c['category']]}   [dim]难度[/dim] {c['difficulty']}   "
        f"[dim]分值[/dim] {c['points']}\n"
        f"[dim]考点[/dim] {c['technique']}\n"
        f"[dim]限时[/dim] {c.get('timeout', 240)}s",
        title=c["name"], color="bright_cyan")
    d = LAB / "challenges" / c["category"] / c["name"] / "src"
    if d.exists():
        files = sorted(p.name for p in d.iterdir())
        the.kv("附件", ", ".join(files))
    else:
        the.warn("材料未生成: python ctf.py gen " + c["name"])
    the.info(f"提示: python ctf.py hint {c['name']} 1")
    import learning
    the.panel(learning.challenge_knowledge(c)['markdown'], title="本题知识点", color="bright_cyan")
    the.info(f"完成: python ctf.py submit {c['name']}   (填入正确 flag 才算完成)")


def cmd_hint(args):
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    hints = c.get("hints", [])
    if not hints:
        print("(该题没有提示)")
        return
    n = args.level or len(hints)
    lines = []
    for i in range(min(n, len(hints))):
        lines.append(f"[yellow]提示 {i + 1}/{len(hints)}[/yellow]  {hints[i]}")
    args.ui_obj.panel("\n".join(lines), title=f"{c['name']} 提示", color="yellow")


def cmd_flag(args):
    import progress as PG
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    # 与网页端一致：看答案就打「看过答案」标记，避免白嫖「独立解出」
    PG.peek(c)
    args.ui_obj.panel(
        f"[bold green]{c['flag']}[/bold green]\n\n"
        f"[dim]已标记「看过答案」(不计入独立解出)。看答案不会记为完成 —— "
        f"要完成本题请在题面页或 `python ctf.py submit {c['name']}` 里提交 flag。[/dim]",
        title=f"{c['name']} 答案", color="green")


def cmd_submit(args):
    """提交 flag —— 唯一能把题目记为完成的入口"""
    import progress as PG
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}   (python ctf.py list 查看全部)")
        sys.exit(1)
    the = args.ui_obj
    the.panel(f"[bold]{c['name']}[/bold]  [dim]{CATEGORY_CN[c['category']]} · "
              f"{c['difficulty']} · {c['points']} 分[/dim]\n\n{c['description']}",
              title="提交 flag", color="bright_cyan")

    raw = args.flag
    if raw is None:
        try:
            raw = input("  flag > ")
        except (EOFError, KeyboardInterrupt):
            the.info("已取消")
            return

    r = PG.submit(c, raw)
    if not r["correct"]:
        the.err(r["message"])
        the.info(f"已提交 {r['attempts']} 次 · 提示: python ctf.py hint {c['name']} 1")
        sys.exit(1)
    if r["first"]:
        the.ok(f"flag 正确   +{r['awarded']} 分")
    else:
        the.ok("flag 正确 (本题此前已完成, 不重复计分)")
    if r["peeked"]:
        the.warn("本题看过答案 —— 仍算完成, 但不计入「独立解出」")
    s = PG.stats(index)
    the.info(f"进度 {s['solved']}/{s['total']} 题 · "
             f"{s['solved_points']}/{s['total_points']} 分 · 独立解出 {s['clean']} 题")


def cmd_progress(args):
    """做题进度总览"""
    import progress as PG
    index, _ = load_index()
    the = args.ui_obj
    rows = []
    for r in PG.by_category(index, CATEGORY_ORDER):
        cat = r["category"]
        pct = f"{r['solved'] * 100 // r['total']}%" if r["total"] else "—"
        rows.append([CATEGORY_CN.get(cat, cat), f"{r['solved']}/{r['total']}", pct,
                     f"{r['solved_points']}/{r['points']}"])
    the.table("分类进度", ["分类", "已完成", "比例", "得分"], rows)

    s = PG.stats(index)
    the.panel(
        f"[bold]{s['solved']}[/bold]/{s['total']} 题   "
        f"[bold]{s['solved_points']}[/bold]/{s['total_points']} 分   "
        f"[dim]完成度 {s['percent']}%[/dim]\n"
        f"独立解出 [green]{s['clean']}[/green] 题"
        + (f"   [yellow]看过答案 {s['peeked']}[/yellow] 题" if s["peeked"] else "")
        + f"   [dim]累计提交 {s['attempts']} 次[/dim]",
        title="我的进度", color="bright_cyan")

    recs = PG.load()["records"]
    done = [(n, r) for n, r in recs.items() if r.get("solved") and n in index]
    if not done:
        the.info("还没有完成的题目 —— python ctf.py submit <题目> 提交 flag")
        return
    done.sort(key=lambda kv: (kv[1].get("solved_at") or ""))
    the.table("已完成的题目", ["题目", "分值", "提交次数", "完成时间", "备注"],
              [[n, str(index[n]["points"]), str(r.get("attempts") or 0),
                r.get("solved_at") or "—",
                "看过答案" if r.get("peeked") else ""] for n, r in done])


def cmd_writeup(args):
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    wp = LAB / "challenges" / c["category"] / c["name"] / "solution" / "writeup.md"
    if not wp.exists():
        print("(暂无 writeup)")
        return
    text = wp.read_text(encoding="utf-8")
    the = args.ui_obj
    if the.rich:
        from rich.markdown import Markdown
        the.console.print(Markdown(text), overflow="fold")
    else:
        print(text)


def _instance_dir(c, dest):
    src = LAB / "challenges" / c["category"] / c["name"] / "src"
    if not src.exists():
        return False
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    files = sorted(p.name for p in dest.iterdir())
    readme = (
        f"# {c['name']}\n\n"
        f"- 分类: {CATEGORY_CN[c['category']]}  难度: {c['difficulty']}  分值: {c['points']}\n"
        f"- 考点: {c['technique']}\n\n"
        f"{c['description']}\n\n"
        f"附件: {', '.join(files)}\n\n"
        f"flag 格式: flag{{...}}。逐步提示: `python ctf.py hint {c['name']} 1`\n"
    )
    (dest / "README.md").write_text(readme, encoding="utf-8")
    return True


def _run_one_check(c):
    """跑一题验证, 返回 (status, msg, dt, out)"""
    import instances as INST
    solve = LAB / "challenges" / c["category"] / c["name"] / "solution" / "solve.py"
    if not solve.exists():
        return "SKIP", "无解题脚本", 0.0, ""
    tr = INST.run_reference_solution(c, keep=False)
    dt = tr.get("seconds", 0.0)
    out = (tr.get("stdout") or "") + (tr.get("stderr") or "")
    if not tr.get("ok"):
        detail = " / ".join(s["detail"].replace(chr(10), " ")
                              for s in tr["steps"] if s["status"] == "fail")
        status = "TIMEOUT" if "超时" in detail else "SKIP"
        return status, detail[:120] or "无法运行", dt, out
    if any(s["title"] == "运行超时" for s in tr["steps"]):
        return "TIMEOUT", f">{c.get('timeout', 240)}s", dt, out
    if tr["pass"]:
        return "PASS", "", dt, out
    got = tr.get("flag")
    return "FAIL", (f"flag 不匹配 (得到 {got[:40]})" if got else "未输出 flag"), dt, out


def cmd_check(args):
    index, _ = load_index()
    targets = resolve_targets([args.name])
    the = args.ui_obj
    verbose = args.verbose
    results = []
    many = len(targets) > 1
    prog = the.progress()
    task = None
    with prog:
        if many and the.rich:
            task = prog.add_task(f"验证 {len(targets)} 题", total=len(targets))
        for c in targets:
            status, msg, dt, out = _run_one_check(c)
            results.append((c["name"], status, msg, dt))
            icon = {"PASS": "✔", "FAIL": "✘", "ERROR": "✘", "SKIP": "○", "TIMEOUT": "⏱"}[status]
            color = {"PASS": "green", "FAIL": "red", "ERROR": "red", "SKIP": "dim", "TIMEOUT": "yellow"}[status]
            if the.rich:
                the.console.print(f"[{color}]{icon} {status:<7}[/] {c['name']:<26} {dt:6.1f}s  {msg}")
            else:
                print(f"[{status:<7}] {c['name']:<26} {dt:6.1f}s  {msg}")
            if verbose and status in ("FAIL", "ERROR", "TIMEOUT"):
                print("-" * 60)
                print(out[-2500:])
                print("-" * 60)
            if task is not None:
                prog.update(task, advance=1)
    npass = sum(1 for _, s, _, _ in results if s == "PASS")
    nfail = len(results) - npass
    if many:
        summary = f"通过 [bold green]{npass}[/bold green]/[bold]{len(results)}[/bold]" + (
            f"  [red]失败 {nfail}[/red]" if nfail else "  [green]全部通过 🎉[/green]")
        the.panel(summary, title="验证结果", color="green" if nfail == 0 else "red")
    else:
        the.rule()


def cmd_gen(args):
    index, _ = load_index()
    targets = resolve_targets([args.name])
    the = args.ui_obj
    out_root = (LAB if args.out == "abs" else WLAB) / (args.out or "dist")
    ok = 0
    for c in targets:
        dest = out_root / c["name"]
        if _instance_dir(c, dest):
            the.ok(f"{c['name']}  [dim]→ {dest.relative_to(LAB)}[/dim]")
            ok += 1
        else:
            the.err(f"{c['name']}  缺少 src/, 请先: python ctf.py regen {c['name']}")
    the.info(f"生成 {ok}/{len(targets)} 题 → {out_root}")


def cmd_regen(args):
    targets = resolve_targets([args.name])
    names = {c["name"] for c in targets}
    the = args.ui_obj
    build_scripts = sorted((LAB / "tools").glob("build_*.py"))
    ran = 0
    for bs in build_scripts:
        if bs.name in ("build_common.py", "build_readme.py", "resources.py"):
            continue
        env = dict(os.environ, CTF_REGEN_ONLY=",".join(sorted(names)))
        r = subprocess.run([sys.executable, str(bs)], cwd=str(LAB), env=env,
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            the.err(f"{bs.name} 失败:\n{r.stdout}\n{r.stderr}")
        else:
            ran += 1
            for line in (r.stdout or "").strip().splitlines()[-4:]:
                the.info(line)
    the.info(f"重新生成完成 ({ran} 个出题脚本)")


def cmd_verify(args):
    """展示验证全过程: 实例目录 / 运行的脚本 / 输出 / 比对"""
    index, _ = load_index()
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    import instances as INST
    the = args.ui_obj
    tr = INST.run_reference_solution(c, keep=args.keep)
    the.header(f"验证 {c['name']}  (参考题解)")
    for s in tr["steps"]:
        mark = {"ok": "✔", "fail": "✘", "info": "•"}.get(s["status"], "•")
        color = {"ok": "green", "fail": "red", "info": "cyan"}.get(s["status"], "cyan")
        detail = s["detail"]
        if the.rich:
            the.console.print(f"[{color}]{mark}[/{color}] [bold]{s['n']}. {s['title']}[/bold]")
            if detail:
                for line in str(detail).splitlines():
                    the.console.print(f"    [dim]{line}[/dim]")
        else:
            print(f"{mark} {s['n']}. {s['title']}")
            for line in str(detail).splitlines():
                print("    " + line)
    if tr.get("stdout") or tr.get("stderr"):
        the.rule("脚本输出")
        print(tr.get("stdout") or "")
        if tr.get("stderr"):
            print("--- stderr ---")
            print(tr["stderr"])
    the.rule()
    if tr["pass"]:
        the.ok(f"PASS  {tr['seconds']}s")
    else:
        the.err(f"{'FAIL' if tr.get('flag') else 'NO FLAG'}  {tr['seconds']}s")


def cmd_instance(args):
    """启动 / 停止 / 查看题目服务实例"""
    index, _ = load_index()
    import instances as INST
    the = args.ui_obj
    if args.action == "list":
        items = INST.list_servers()
        if not items:
            the.info("没有正在运行的服务实例")
            return
        the.table("运行中的实例", ["题目", "端口", "脚本", "实例目录"],
                  [[i["name"], i["port"], i["script"], i["instance"]] for i in items])
        return
    c = index.get(args.name)
    if not c:
        U.err(f"未知题目: {args.name}")
        sys.exit(1)
    if args.action == "stop":
        r = INST.stop_server(c["name"])
        (the.ok if r["ok"] else the.err)("已停止" if r["ok"] else r.get("error", "停止失败"))
        return
    r = INST.start_server(c)
    if not r["ok"]:
        the.err(r.get("error", "启动失败"))
        sys.exit(1)
    the.panel(f"端口  [bold]{r['port']}[/bold]\n"
              f"READY {r['ready']}\n"
              f"实例  {r['instance']}\n\n"
              f"[dim]连接: nc 127.0.0.1 {r['port']}\n"
              f"停止: python ctf.py instance {c['name']} stop[/dim]",
              title=f"{c['name']} 服务实例", color="green")
    if args.follow:
        the.info("按 Ctrl+C 停止服务")
        try:
            while True:
                time.sleep(1)
                alive = [x for x in INST.list_servers() if x["name"] == c["name"]]
                if not alive or not alive[0]["alive"]:
                    the.warn("服务进程已退出")
                    break
        except KeyboardInterrupt:
            INST.stop_server(c["name"])
            the.info("已停止")


def cmd_doctor(args):
    the = args.ui_obj
    import resources as RES
    the.header("外部资源探测 (John the Ripper / rockyou / hashcat / 7-Zip)")
    res = RES.get_resources(rescan=args.rescan)
    rows = []
    j = res.get("john")
    rows.append(["John the Ripper", "✔ 已找到" if j else "✗ 未找到",
                 f"{j['version']}" if j else "—", j["exe"] if j else "—"])
    rk = res.get("rockyou")
    rows.append(["rockyou.txt", "✔ 已找到" if rk else "✗ 未找到",
                 f"{rk['lines']:,} 行" if rk and rk.get("lines") else "—",
                 rk["path"] if rk else "—"])
    hc = res.get("hashcat")
    rows.append(["hashcat", "✔ 已找到" if hc else "✗ 未找到", "—", hc["exe"] if hc else "—"])
    sz = res.get("sevenzip")
    rows.append(["7-Zip", "✔ 已找到" if sz else "✗ 未找到", "—", sz["exe"] if sz else "—"])
    the.table(None, ["工具/字典", "状态", "版本/规模", "路径"], rows)
    need = ("cracking 分类的题目依赖 John the Ripper 与 rockyou；缺失时该类题目会以 "
            "SKIPPED-RESOURCE 提示并跳过。重新扫描: python ctf.py doctor --rescan")
    the.panel(need, title="说明", color="cyan")
    # 各题的资源依赖检查
    index, _ = load_index()
    dep = [c for c in index.values() if c.get("requires")]
    if dep:
        rows2 = []
        for c in dep:
            missing = [r for r in c["requires"] if not res.get(r)]
            rows2.append([c["name"], ", ".join(c["requires"]),
                          "✔ 可解" if not missing else f"✗ 缺 {', '.join(missing)}"])
        the.table("题目资源依赖", ["题目", "需要", "状态"], rows2)


# ------------------------------------------------------------------ 交互模式

def _pick(index, the, cat=None):
    """交互选题, 返回题目名或 None"""
    while True:
        chs = [(n, c) for n, c in index.items() if cat is None or c["category"] == cat]
        chs.sort(key=lambda x: (CATEGORY_ORDER.index(x[1]["category"]), x[1]["points"]))
        the.rule(f"选题 ({CATEGORY_CN.get(cat, '全部分类')})" if cat else "选题")
        page = 1
        PAGE = 12
        while True:
            chunk = chs[(page - 1) * PAGE: page * PAGE]
            rows = []
            for i, (n, c) in enumerate(chunk, (page - 1) * PAGE + 1):
                src = (LAB / "challenges" / c["category"] / c["name"] / "src").exists()
                rows.append([str(i), n, c["difficulty"], str(c["points"]),
                             c["technique"][:34], "✓" if src else "—"])
            the.table(None, ["#", "题目", "难度", "分", "考点", "材料"], rows)
            the.info(f"第 {page}/{max(1, (len(chs) + PAGE - 1)//PAGE)} 页 — 输入编号选题, "
                     f"[n]下一页 [p]上一页 [a]全部 [b]返回")
            choice = input("  > ").strip().lower()
            if choice == "n":
                page = min(page + 1, max(1, (len(chs) + PAGE - 1) // PAGE)); continue
            if choice == "p":
                page = max(1, page - 1); continue
            if choice == "b":
                return None
            if choice == "a":
                cat = None; break
            if choice.isdigit() and 1 <= int(choice) <= len(chs):
                return chs[int(choice) - 1][0]
            the.warn("无效输入")


def cmd_ui(args):
    index, _ = load_index()
    the = args.ui_obj
    while True:
        the.rule("CTF Crypto Lab")
        if the.rich:
            the.console.print("[bold bright_cyan]  🔐 CTF Crypto Lab[/bold bright_cyan]  "
                              "[dim]密码学方向本地训练场[/dim]\n")
        rows = [["1", "题目库", "浏览 / 领取 / 提交 flag"],
                ["2", "我的进度", "已完成 / 得分 / 分类统计"],
                ["3", "自洽性检查", "check all — 跑参考题解核对题目材料 (不计进度)"],
                ["4", "资源探测", "John the Ripper / rockyou / hashcat / 7-Zip"],
                ["5", "题目站 (Web)", "多页面网页界面 — 题面 / 附件 / 提示 / 提交 flag"],
                ["6", "密码工具箱 (Web)", "独立工具界面 — 编码 / 古典 / RSA / 格攻击 等"],
                ["7", "题目一览", "list 表格视图"],
                ["0", "退出", ""]]
        the.table(None, ["#", "功能", "说明"], rows)
        choice = input("  选择 > ").strip()
        if choice == "0":
            the.info("bye 👋")
            return
        if choice == "1":
            cur_cat = None
            while True:
                the.rule("分类")
                opts = [(str(i + 1), cat) for i, cat in enumerate(CATEGORY_ORDER)
                        if any(c["category"] == cat for c in index.values())]
                the.table(None, ["#", "分类"],
                          [[o, f"{CATEGORY_CN[c]} ({c}) — {sum(1 for x in index.values() if x['category'] == c)} 题"]
                           for o, c in opts] + [["a", "全部分类"], ["b", "返回"]])
                ch = input("  分类 > ").strip().lower()
                if ch == "b":
                    break
                if ch == "a":
                    cur_cat = None
                else:
                    m = dict(opts).get(ch)
                    if m:
                        cur_cat = m
                    else:
                        the.warn("无效输入"); continue
                while True:
                    nm = _pick(index, the, cur_cat)
                    if not nm:
                        break
                    c = index[nm]
                    cmd_info(_NS(name=nm, ui_obj=the))
                    while True:
                        the.info(f"[b]返回  [g]gen 领取  [s]submit 提交flag  [c]check 自检  "
                                 f"[h]hint 提示  [w]writeup 题解  [f]看答案(不计分)  [o]打开目录")
                        a = input(f"  [{nm}] > ").strip().lower()
                        if a == "b":
                            break
                        elif a == "g":
                            cmd_gen(_NS(name=nm, out=None, ui_obj=the))
                        elif a == "s":
                            cmd_submit(_NS(name=nm, flag=None, ui_obj=the))
                        elif a == "c":
                            cmd_check(_NS(name=nm, verbose=False, ui_obj=the))
                        elif a == "h":
                            cmd_hint(_NS(name=nm, level=None, ui_obj=the))
                        elif a == "w":
                            cmd_writeup(_NS(name=nm, ui_obj=the))
                        elif a == "f":
                            cmd_flag(_NS(name=nm, ui_obj=the))
                        elif a == "o":
                            d = LAB / "dist" / nm
                            d.mkdir(parents=True, exist_ok=True)
                            if not _instance_dir(c, d):
                                _instance_dir(c, d)
                            os.startfile(str(d))
                        else:
                            the.warn("无效输入")
        elif choice == "2":
            cmd_progress(_NS(ui_obj=the))
        elif choice == "3":
            cmd_check(_NS(name="all", verbose=False, ui_obj=the))
        elif choice == "4":
            cmd_doctor(_NS(rescan=False, ui_obj=the))
        elif choice == "5":
            cmd_serve(_NS(port=8787, no_browser=False, ui_obj=the))
        elif choice == "6":
            cmd_toolkit(_NS(port=8788, no_browser=False, ui_obj=the))
        elif choice == "7":
            cmd_list(_NS(ui_obj=the))
        else:
            the.warn("无效输入")


class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# ------------------------------------------------------------------ main

def _run_py_mode(argv):
    """打包成 exe 后充当 Python 解释器: <exe> --run-py <script> [args...]"""
    import runpy
    if len(argv) < 3:
        print("usage: --run-py <script.py> [args...]", file=sys.stderr)
        return 2
    script = argv[2]
    sys.path.insert(0, str(LAB / "lib"))
    sys.path.insert(0, str(LAB))
    sys.argv = [script] + argv[3:]
    try:
        runpy.run_path(script, run_name="__main__")
        return 0
    except SystemExit as e:
        return int(e.code or 0)


def main():
    if len(sys.argv) > 1:
        a1 = sys.argv[1]
        if a1 == "--run-py":
            raise SystemExit(_run_py_mode(sys.argv))
        # 打包成 exe 后, 让 `sys.executable script.py` 也能工作 (各题 solve.py
        # 会用这种方式启动 server.py / oracle.py / verify.py)
        if (labenv.is_frozen() and not a1.startswith("-")
                and a1.lower().endswith(".py") and Path(a1).is_file()):
            raise SystemExit(_run_py_mode([sys.argv[0], "--run-py"] + sys.argv[1:]))
    plain = "--plain" in sys.argv
    argv = [a for a in sys.argv[1:] if a != "--plain"]
    the = UI(force_plain=plain)
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="CTF Crypto Lab 平台 (v2)")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("list", help="题目一览").set_defaults(fn=cmd_list, ui_obj=the)
    p = sub.add_parser("info", help="题目详情"); p.add_argument("name"); p.set_defaults(fn=cmd_info, ui_obj=the)
    p = sub.add_parser("hint", help="逐步提示"); p.add_argument("name")
    p.add_argument("level", nargs="?", type=int); p.set_defaults(fn=cmd_hint, ui_obj=the)
    p = sub.add_parser("flag", help="查看答案 (不计入完成)"); p.add_argument("name"); p.set_defaults(fn=cmd_flag, ui_obj=the)
    p = sub.add_parser("submit", help="提交 flag 判题 (唯一记完成的方式)")
    p.add_argument("name"); p.add_argument("--flag", default=None, help="直接给出 flag, 不进交互")
    p.set_defaults(fn=cmd_submit, ui_obj=the)
    sub.add_parser("progress", help="查看做题进度").set_defaults(fn=cmd_progress, ui_obj=the)
    p = sub.add_parser("gen", help="生成玩家文件"); p.add_argument("name")
    p.add_argument("--out", default=None); p.set_defaults(fn=cmd_gen, ui_obj=the)
    p = sub.add_parser("check", help="验证解题脚本"); p.add_argument("name")
    p.add_argument("--verbose", action="store_true"); p.set_defaults(fn=cmd_check, ui_obj=the)
    p = sub.add_parser("writeup", help="查看题解"); p.add_argument("name"); p.set_defaults(fn=cmd_writeup, ui_obj=the)
    p = sub.add_parser("regen", help="重新生成题目材料"); p.add_argument("name"); p.set_defaults(fn=cmd_regen, ui_obj=the)
    p = sub.add_parser("verify", help="验证参考题解 (显示完整过程)")
    p.add_argument("name")
    p.add_argument("--keep", action="store_true", help="保留实例目录")
    p.set_defaults(fn=cmd_verify, ui_obj=the)
    p = sub.add_parser("instance", help="题目服务实例 (start/stop/list)")
    p.add_argument("name", nargs="?", default="")
    p.add_argument("action", nargs="?", default="list", choices=["start", "stop", "list"])
    p.add_argument("--follow", action="store_true", help="启动后保持前台")
    p.set_defaults(fn=cmd_instance, ui_obj=the)
    p = sub.add_parser("doctor", help="探测外部资源 (JtR/rockyou/hashcat)")
    p.add_argument("--rescan", action="store_true"); p.set_defaults(fn=cmd_doctor, ui_obj=the)
    p = sub.add_parser("serve", help="启动题目站 (Web)"); p.add_argument("--port", type=int, default=8787)
    p.add_argument("--no-browser", action="store_true"); p.set_defaults(fn=cmd_serve, ui_obj=the)
    p = sub.add_parser("toolkit", help="启动密码工具箱 (独立 Web 界面)")
    p.add_argument("--port", type=int, default=8788)
    p.add_argument("--no-browser", action="store_true"); p.set_defaults(fn=cmd_toolkit, ui_obj=the)
    p = sub.add_parser("web", help="同时启动题目站 + 工具箱")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--toolkit-port", type=int, default=8788)
    p.add_argument("--no-browser", action="store_true"); p.set_defaults(fn=cmd_web, ui_obj=the)
    sub.add_parser("ui", help="交互式模式").set_defaults(fn=cmd_ui, ui_obj=the)
    p = sub.add_parser("version", help="显示版本")
    p.set_defaults(fn=lambda a: print(VERSION), ui_obj=the)

    if not argv:
        if labenv.is_frozen():          # 双击 exe → 直接起 Web 界面
            cmd_web(_NS(port=8787, toolkit_port=8788, no_browser=False,
                        ui_obj=the))
        else:
            cmd_ui(_NS(ui_obj=the))
        return
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        cmd_ui(_NS(ui_obj=the))
        return
    args.fn(args)


def _pick_port(preferred: int, tries: int = 40) -> int:
    """从 preferred 开始找一个空闲端口 (端口被占用时自动顺延)"""
    import socket
    for p in range(preferred, preferred + tries):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise SystemExit(f"从 {preferred} 起的 {tries} 个端口都被占用")


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def cmd_serve(args):
    the = args.ui_obj
    from webconsole import serve as _serve
    args.port = _pick_port(args.port)
    url = f"http://127.0.0.1:{args.port}"
    the.panel(f"[bold bright_cyan]{url}[/bold bright_cyan]\n"
              f"[dim]题目站: 概览 / 题目库 / 完整题面页 (描述·附件·提示·题解·验证)\n"
              f"工具箱是独立界面: python ctf.py toolkit  (默认 8788)\n"
              f"按 Ctrl+C 停止服务[/dim]", title="题目站", color="bright_cyan")
    if not args.no_browser:
        webbrowser.open(url)
    _serve(port=args.port, quiet=True)


def cmd_toolkit(args):
    the = args.ui_obj
    from toolkit_web import serve as _serve
    args.port = _pick_port(args.port)
    url = f"http://127.0.0.1:{args.port}"
    the.panel(f"[bold bright_cyan]{url}[/bold bright_cyan]\n"
              f"[dim]密码工具箱 (独立界面): 编码 / 古典 / XOR / 哈希 / RSA / 离散对数 / PRNG / 格\n"
              f"所有计算在本地完成, 结果带步骤说明\n"
              f"按 Ctrl+C 停止服务[/dim]", title="密码工具箱", color="bright_cyan")
    if not args.no_browser:
        webbrowser.open(url)
    _serve(port=args.port, quiet=True)


def cmd_web(args):
    """同时启动题目站与工具箱 (端口自动避让, 就绪后再开浏览器)"""
    import threading
    the = args.ui_obj
    from webconsole import serve as _console
    from toolkit_web import serve as _toolkit
    p1 = _pick_port(args.port)
    p2 = _pick_port(args.toolkit_port if args.toolkit_port != p1 else p1 + 1)
    u1, u2 = f"http://127.0.0.1:{p1}", f"http://127.0.0.1:{p2}"
    the.panel(f"题目站  [bold bright_cyan]{u1}[/bold bright_cyan]\n"
              f"工具箱  [bold bright_cyan]{u2}[/bold bright_cyan]\n"
              f"[dim]题目站可跳转工具箱; 按 Ctrl+C 或关闭窗口停止[/dim]",
              title="CTF Crypto Lab", color="bright_cyan")
    threading.Thread(target=_toolkit, kwargs={"port": p2, "quiet": True},
                     daemon=True).start()
    threading.Thread(target=_console, kwargs={"port": p1, "quiet": True,
                                              "toolkit_port": p2},
                     daemon=True).start()
    ok1, ok2 = _wait_port(p1), _wait_port(p2)
    if not (ok1 and ok2):
        the.err(f"服务启动失败 (题目站 {'✓' if ok1 else '✗'} / 工具箱 {'✓' if ok2 else '✗'})")
        return
    if not args.no_browser:
        webbrowser.open(u1)
    the.info("已在浏览器打开; 关闭此窗口即可停止服务")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
