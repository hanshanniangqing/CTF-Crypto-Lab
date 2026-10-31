# -*- coding: utf-8 -*-
"""
webconsole.py — CTF Crypto Lab 题目站 (多页面 Web 应用, 纯标准库)

  python ctf.py serve [--port 8787]

路由 (hash):  #/ 概览   #/challenges 题目库   #/c/<name> 题面页   #/resources 资源
题面页: 描述 / 附件预览与下载 / 分步提示 / 题解 / 在线验证, 支持上一题下一题。
"""
import json
import mimetypes
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import labenv  # noqa: E402

LAB = labenv.LAB
WLAB = labenv.WLAB
sys.path.insert(0, str(LAB / "lib"))
sys.path.insert(0, str(LAB / "tools"))
sys.path.insert(0, str(LAB))

from webbase import BASE_CSS, JS_HELPERS  # noqa: E402
import instances as INST  # noqa: E402
import progress as PG  # noqa: E402

TOOLKIT_PORT = None    # 由 `ctf.py web` 注入真实端口；None 时运行时探测

CAT_CN = {
    "classical": "古典密码", "symmetric": "对称密码", "stream": "流密码与PRNG",
    "rsa": "RSA", "pubkey": "公钥与离散对数", "hash": "哈希", "lattice": "格密码",
    "cracking": "口令破解实战",
}
CAT_ICON = {
    "classical": "🏛", "symmetric": "🔐", "stream": "🌊", "rsa": "🧮",
    "pubkey": "🔑", "hash": "#", "lattice": "🔷", "cracking": "🗝",
}
CAT_COLOR = {
    "classical": "#34d399", "symmetric": "#22d3ee", "stream": "#60a5fa", "rsa": "#f87171",
    "pubkey": "#fb923c", "hash": "#fbbf24", "lattice": "#a78bfa", "cracking": "#f472b6",
}
ORDER = ["classical", "symmetric", "stream", "rsa", "pubkey", "hash", "lattice", "cracking"]


def _version():
    try:
        from ctf import VERSION as V
        return V.replace("CTF Crypto Lab ", "").lstrip("vV")
    except Exception:
        return "3.1"


def _index():
    data = json.loads((LAB / "challenges" / "index.json").read_text(encoding="utf-8"))
    return {c["name"]: c for c in data["challenges"]}


def _safe_src_file(name, fname):
    c = _index().get(name)
    if not c or not fname or "/" in fname or "\\" in fname or ".." in fname:
        return None
    p = LAB / "challenges" / c["category"] / c["name"] / "src" / fname
    return p if p.is_file() else None


_BIN_EXT = {".zip", ".gz", ".7z", ".rar", ".tar", ".png", ".jpg", ".jpeg",
            ".gif", ".webp", ".bmp", ".pcap", ".exe", ".dll", ".so", ".pyd",
            ".pyc", ".pdf", ".der"}


def _looks_binary(p: Path) -> bool:
    """按扩展名 + NUL 字节粗判，避免把二进制塞进 <pre> 变成乱码"""
    if p.suffix.lower() in _BIN_EXT:
        return True
    try:
        with open(p, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def _http_local(url, timeout=1.0):
    """本机探测必须绕过系统代理 —— 否则 127.0.0.1 会被代理拦成 502"""
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}),
                     timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def find_toolkit(preferred=None):
    """
    工具箱与题目站是两个独立进程，端口可能被占用后顺延，
    所以链接不能写死 8788 —— 实际探测一下哪个端口在跑工具箱。
    """
    import socket
    ports = []
    if preferred:
        ports.append(int(preferred))
    for p in range(8788, 8798):
        if p not in ports:
            ports.append(p)
    for p in ports:
        try:
            with socket.socket() as s:
                s.settimeout(0.25)
                if s.connect_ex(("127.0.0.1", p)) != 0:
                    continue
            data = _http_local(f"http://127.0.0.1:{p}/api/tools")
            if isinstance(data, dict) and data.get("tools"):
                return {"ok": True, "url": f"http://127.0.0.1:{p}",
                        "port": p, "count": len(data["tools"])}
        except (OSError, ValueError):
            continue
    return {"ok": False, "url": None, "port": None,
            "hint": "工具箱没在运行 —— 新开一个窗口执行 python ctf.py toolkit"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        """读请求体 JSON；空体/坏 JSON 一律当 {} —— 判题接口不能因解析失败 500"""
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            if not ln:
                return {}
            data = json.loads(self.rfile.read(ln).decode("utf-8") or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        path = urllib.parse.unquote(self.path.split("?")[0])
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")

        if path == "/api/index":
            idx = _index()
            out = []
            for c in idx.values():
                src = LAB / "challenges" / c["category"] / c["name"] / "src"
                out.append({
                    "name": c["name"], "category": c["category"],
                    "category_cn": CAT_CN.get(c["category"], c["category"]),
                    "difficulty": c["difficulty"], "points": c["points"],
                    "technique": c["technique"], "description": c["description"],
                    "hints_count": len(c.get("hints", [])),
                    "ready": bool(src.exists() and any(src.iterdir())),
                    "requires": c.get("requires", []),
                    "timeout": c.get("timeout", 240),
                    "server": bool(INST.server_script(c)),
                    "server_script": (INST.server_script(c).name
                                      if INST.server_script(c) else None),
                    "oracle": bool(INST.oracle_script(c)),
                    "run_hint": INST.run_hint(c),
                })
            return self._json({"challenges": out,
                               "version": _version(),
                               "cats": [{"k": k, "cn": CAT_CN[k], "icon": CAT_ICON[k],
                                         "color": CAT_COLOR[k]} for k in ORDER],
                               "wordlist": self._wordlist_stats()})

        m = re.match(r"^/api/hints/([\w\-]+)$", path)
        if m:
            c = _index().get(m.group(1))
            return self._json({"hints": c.get("hints", [])}) if c else self._json({"error": "no challenge"}, 404)

        # 进度只在服务端 —— 只有提交正确 flag 才会写进这里
        if path == "/api/progress":
            return self._json(PG.summary(_index()))

        m = re.match(r"^/api/writeup/([\w\-]+)$", path)
        if m:
            c = _index().get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            wp = LAB / "challenges" / c["category"] / c["name"] / "solution" / "writeup.md"
            return self._json({"writeup": wp.read_text(encoding="utf-8") if wp.exists() else ""})

        # 题目材料一次性取回：文本直接内联展开，二进制给下载链接
        m = re.match(r"^/api/material/([\w\-]+)$", path)
        if m:
            c = _index().get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            d = LAB / "challenges" / c["category"] / c["name"] / "src"
            items = []
            if d.exists():
                for p in sorted(d.iterdir()):
                    if not p.is_file():
                        continue
                    size = p.stat().st_size
                    item = {"name": p.name, "size": size}
                    text = None
                    if not _looks_binary(p):
                        try:
                            text = p.read_text(encoding="utf-8", errors="replace")
                        except OSError:
                            text = None
                    if text is None:
                        item["binary"] = True
                    else:
                        item["text"] = text
                        item["binary"] = False
                        item["lines"] = text.count("\n") + (0 if text.endswith("\n") else 1)
                    items.append(item)
            return self._json({"name": c["name"], "files": items,
                               "dir": f"challenges/{c['category']}/{c['name']}/src",
                               "gen": (WLAB / "dist" / c["name"]).exists()})

        m = re.match(r"^/api/download/([\w\-]+)/(.+)$", path)
        if m:
            p = _safe_src_file(m.group(1), m.group(2))
            if not p:
                return self._json({"error": "no such file"}, 404)
            ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            if ctype.startswith("text/"):
                ctype += "; charset=utf-8"
            return self._send(200, p.read_bytes(), ctype,
                              {"Content-Disposition": f'attachment; filename="{p.name}"'})

        m = re.match(r"^/api/script/([\w\-]+)$", path)
        if m:
            c = _index().get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            sp = LAB / "challenges" / c["category"] / c["name"] / "solution" / "solve.py"
            if not sp.exists():
                return self._json({"error": "no solution script"}, 404)
            return self._json({"name": sp.name, "path": str(sp.relative_to(LAB)),
                               "text": sp.read_text(encoding="utf-8"),
                               "spoiler": True})

        if path == "/api/instances":
            return self._json({"instances": INST.list_servers()})

        if path == "/api/resources":
            import resources as RES
            return self._json(RES.get_resources())

        # 工具箱是独立进程，端口可能顺延 —— 前端据此拿到真实地址
        if path == "/api/toolkit":
            return self._json(find_toolkit(TOOLKIT_PORT))

        return self._json({"error": "not found"}, 404)

    @staticmethod
    def _wordlist_stats():
        try:
            import resources as RES
            rk = RES.get_resources().get("rockyou")
            return {"rockyou": bool(rk), "lines": (rk or {}).get("lines")}
        except Exception:
            return {"rockyou": False, "lines": None}

    def do_POST(self):
        path = urllib.parse.unquote(self.path)

        # ---- 判题：填入正确 flag 才记完成（唯一的进度写入入口）----
        m = re.match(r"^/api/submit/([\w\-]+)$", path)
        if m:
            idx = _index()
            c = idx.get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            res = PG.submit(c, self._body().get("flag"))
            res["progress"] = PG.summary(idx)
            return self._json(res)

        # ---- 放弃：给答案，但只打「已看答案」标记，不记完成 ----
        m = re.match(r"^/api/giveup/([\w\-]+)$", path)
        if m:
            idx = _index()
            c = idx.get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            res = PG.peek(c)
            res["progress"] = PG.summary(idx)
            return self._json(res)

        if path == "/api/progress/reset":
            if not self._body().get("confirm"):
                return self._json({"ok": False, "error": "需要 {confirm:true}"}, 400)
            PG.reset()
            return self._json({"ok": True, "progress": PG.summary(_index())})

        m = re.match(r"^/api/check/([\w\-]+)$", path)
        if m:
            from ctf import _run_one_check, load_index
            c = load_index()[0].get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            status, msg, dt, _out = _run_one_check(c)
            return self._json({"name": c["name"], "status": status, "msg": msg,
                               "seconds": round(dt, 1)})

        m = re.match(r"^/api/gen/([\w\-]+)$", path)
        if m:
            from ctf import _instance_dir, load_index
            c = load_index()[0].get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            dest = WLAB / "dist" / c["name"]
            ok = _instance_dir(c, dest)
            return self._json({"ok": bool(ok), "dest": f"dist/{c['name']}" if ok else None})

        m = re.match(r"^/api/verify/([\w\-]+)$", path)
        if m:
            from ctf import load_index
            c = load_index()[0].get(m.group(1))
            if not c:
                return self._json({"error": "no challenge"}, 404)
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}") if ln else {}
            except (ValueError, UnicodeDecodeError):
                body = {}
            tr = INST.run_reference_solution(c, keep=bool(body.get("keep")))
            return self._json(tr)

        m = re.match(r"^/api/instance/([\w\-]+)/(start|stop)$", path)
        if m:
            from ctf import load_index
            name, action = m.group(1), m.group(2)
            if action == "stop":
                return self._json(INST.stop_server(name))
            c = load_index()[0].get(name)
            if not c:
                return self._json({"error": "no challenge"}, 404)
            if not INST.server_script(c):
                return self._json({
                    "ok": False,
                    "error": "该题不是网络服务题"
                             + ("（oracle.py 是 stdin/stdout 工具，用命令行运行）"
                                if INST.oracle_script(c) else "")})
            return self._json(INST.start_server(c))

        m = re.match(r"^/api/instance/([\w\-]+)$", path)
        if m:
            items = [x for x in INST.list_servers() if x["name"] == m.group(1)]
            return self._json({"instance": items[0] if items else None})

        if path == "/api/reveal":
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}") if ln else {}
            except (ValueError, UnicodeDecodeError):
                body = {}
            target = Path(str(body.get("path") or "")).resolve()
            try:
                target.relative_to(WLAB.resolve())
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "路径不在可写目录内"}, 400)
            if not target.exists():
                return self._json({"ok": False, "error": "目录不存在"}, 404)
            try:
                if os.name == "nt":
                    os.startfile(str(target))
                else:
                    import subprocess as _sp
                    _sp.Popen(["xdg-open", str(target)])
            except OSError as e:
                return self._json({"ok": False, "error": str(e)})
            return self._json({"ok": True, "path": str(target)})

        if path == "/api/gen-all":
            from ctf import _instance_dir, load_index
            idx = load_index()[0]
            ok = 0
            for c in idx.values():
                if _instance_dir(c, WLAB / "dist" / c["name"]):
                    ok += 1
            return self._json({"ok": True, "count": ok, "total": len(idx)})

        return self._json({"error": "not found"}, 404)


# ======================================================================
PAGE_RAW = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF Crypto Lab</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='88'>%F0%9F%94%90</text></svg>">
<style>__CSS__</style>
</head>
<body>
<div class="shell">
  <aside class="side">
    <div class="brand"><span class="dot"></span><div>CTF Crypto Lab<small>密码学本地训练场 · <span id="brandVer">v—</span></small></div></div>
    <nav class="nav" id="nav">
      <a href="#/" data-r="home"><span class="ic">◈</span><span class="tx">概览</span></a>
      <a href="#/challenges" data-r="ch"><span class="ic">▤</span><span class="tx">题目库</span></a>
      <a href="#/resources" data-r="res"><span class="ic">🩺</span><span class="tx">资源探测</span></a>
      <div class="grp">工具</div>
      <a href="#/resources" id="navToolkit"><span class="ic">🧰</span><span class="tx" id="navToolkitTx">密码工具箱</span></a>
      <div class="grp">状态</div>
      <a href="#/" style="cursor:default"><span class="ic">◐</span><span class="tx" id="navprog-tx">0 / 0 完成</span></a>
    </nav>
    <div class="foot">提交 flag 才算完成<br>进度: <span class="mono">progress.json</span><br>工具箱: <span class="mono">ctf.py toolkit</span></div>
  </aside>
  <div class="main">
    <div class="topbar">
      <div class="title" id="crumb">概览</div>
      <div class="sp"></div>
      <div class="row tiny muted" id="statline"></div>
    </div>
    <div class="page" id="view"><div class="empty"><div class="big">◌</div>加载中…</div></div>
  </div>
</div>
<div id="toast"></div>
<script>
__JS__
</script>
<script>
const CATS=[], CIB={};
let CH=[], RES=null;

/* 进度只存在服务端 (/api/progress) → 本机 progress.json，CLI 与网页共用同一份。
   网页不提供「手动标记完成」：只有提交正确的 flag 才会变成已完成。 */
let PG={records:{},stats:{total:0,total_points:0,solved:0,solved_points:0,
  clean:0,clean_points:0,peeked:0,attempts:0,percent:0}};
function doneSet(){const s=new Set();
  for(const n in (PG.records||{})){const r=PG.records[n];if(r&&r.solved)s.add(n);}return s;}
function recOf(n){return (PG.records||{})[n]||{};}
async function refreshProgress(){
  try{PG=await apiGet("/api/progress");}catch(e){}
  paintProgress();
}
function paintProgress(){
  const st=PG.stats||{};
  const el=$("#statline");
  if(el)el.innerHTML=`<span>题目 <b style="color:var(--txt)">${st.solved||0}</b>/${st.total||0}</span>
    <span>得分 <b style="color:var(--acc2)">${st.solved_points||0}</b>/${st.total_points||0}</span>
    ${st.peeked?`<span>看答案 <b style="color:var(--warn)">${st.peeked}</b></span>`:""}
    <progress max="100" value="${st.percent||0}"></progress>`;
  const nt=$("#navprog-tx");if(nt)nt.textContent=`${st.solved||0} / ${st.total||0} 完成`;
}
function statusChip(n){
  const r=recOf(n);
  if(r.solved&&r.peeked)return '<span class="tag peek">已看答案</span>';
  if(r.solved)return '<span class="tag ok">✔ 已完成</span>';
  return '<span class="tag bad">未完成</span>';
}

/* 工具箱是独立进程，端口可能不是 8788 —— 由服务端探测真实地址 */
let TK=null;
function applyToolkit(){
  const a=$("#navToolkit"), tx=$("#navToolkitTx");
  if(!a)return;
  if(TK&&TK.ok){
    a.href=TK.url;a.target="_blank";a.rel="noopener";
    if(tx)tx.textContent="密码工具箱 :"+TK.port+" ↗";
  }else{
    a.href="#/resources";a.removeAttribute("target");
    if(tx)tx.textContent="密码工具箱（未运行）";
  }
}
function renderToolkitBox(){
  const els=$$(".tk-box");
  if(!els.length)return;
  let html;
  if(!TK){html='<span class="muted">探测中…</span>';}
  else if(TK.ok){
    html='工具箱运行中 <a href="'+TK.url+'" target="_blank" rel="noopener">127.0.0.1:'+TK.port+'</a>'
      +' · '+TK.count+' 个工具<br>'
      +'<a class="btn sm" style="margin-top:8px" href="'+TK.url+'" target="_blank" rel="noopener">打开工具箱 ↗</a>';
  }else{
    html='工具箱未运行。新开一个终端执行 <span class="mono">python ctf.py toolkit</span>，'
      +'或用 <span class="mono">python ctf.py web</span> 一次启动两个界面。';
  }
  els.forEach(el=>{el.innerHTML=html;});
}
async function loadToolkit(){
  try{TK=await apiGet("/api/toolkit");}catch(e){TK={ok:false};}
  applyToolkit();renderToolkitBox();
}
function colorOf(cat){return (CIB[cat]&&CIB[cat].color)||"var(--acc)";}
function setNav(r){$$("#nav a[data-r]").forEach(a=>a.classList.toggle("on",a.dataset.r===r));}

/* ---------------- 概览 ---------------- */
function viewHome(){
  setNav("home");$("#crumb").textContent="概览";
  const s=doneSet();
  const st=PG.stats||{};const pts=st.solved_points||0,total=st.total_points||0;
  const cats=CATS.map(cat=>{const list=CH.filter(c=>c.category===cat.k);
    return {cat,list,d:list.filter(c=>s.has(c.name)).length};});
  $("#view").innerHTML=`
  <div class="card pad" style="margin-bottom:14px;background:
     linear-gradient(135deg,rgba(34,211,238,.10),rgba(167,139,250,.09)),var(--panel)">
    <div class="row" style="justify-content:space-between;align-items:flex-start">
      <div>
        <h1 style="margin-bottom:4px">🔐 密码学 CTF 训练场</h1>
        <div class="muted tiny">${CH.length} 道题 · ${total} 分 · 古典密码 → 格密码 / 口令破解实战</div>
      </div>
      <div class="row">
        <button class="btn primary" id="btnGenAll">📥 领取全部题目</button>
        <button class="btn" id="btnCheckAll">🔍 自洽性检查</button>
        <button class="btn ghost" id="btnReset">↺ 重置进度</button>
      </div>
    </div>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-top:18px">
      ${[[CH.length,"题目总数"],[total,"总分"],[st.solved||0,"已完成"],
         [pts,"已得分"],[st.clean||0,"独立解出"]].map(([v,l])=>
        `<div class="card" style="padding:12px 14px;text-align:center">
          <div style="font-size:1.5rem;font-weight:700;color:var(--acc)">${v}</div>
          <div class="tiny muted">${l}</div></div>`).join("")}
    </div>
    <div class="row" style="margin-top:14px;gap:8px">
      <div class="bar" style="flex:1"><i style="width:${st.percent||0}%"></i></div>
      <span class="tiny muted">${st.percent||0}%</span>
    </div>
    <div class="tiny muted" style="margin-top:10px">
      进度保存在本机 <span class="mono">progress.json</span>，与 <span class="mono">python ctf.py submit</span> 共用；
      <b style="color:var(--txt)">只有提交正确的 flag 才会记为完成</b>，看答案不计分。
    </div>
  </div>

  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(290px,1fr));margin-bottom:14px">
    <div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2>分类进度</h2><a class="tiny" href="#/challenges">全部题目 →</a></div>
      ${cats.map(({cat,list,d})=>`
        <div style="margin:9px 0">
          <div class="row tiny" style="justify-content:space-between">
            <span>${cat.icon} ${esc(cat.cn)}</span><span class="muted">${d}/${list.length}</span></div>
          <div class="bar" style="margin-top:4px"><i style="width:${list.length?d*100/list.length:0}%;
            background:${cat.color}"></i></div>
        </div>`).join("")}
    </div>
    <div class="card">
      <h2 style="margin-bottom:10px">外部资源</h2>
      <div id="resMini" class="row" style="gap:14px"><span class="muted tiny">加载中…</span></div>
      <div class="tiny muted" style="margin-top:12px;line-height:1.7">
        cracking 分类的 4 道题使用 John the Ripper + rockyou 真实破解流程。
      </div>
      <div class="tiny muted tk-box" style="margin-top:12px;line-height:1.8;padding-top:12px;
           border-top:1px solid var(--line)"><span class="muted">探测工具箱…</span></div>
      <div class="actions" style="margin-top:12px">
        <a class="btn sm" href="#/resources">依赖详情</a>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:6px">
      <h2>自洽性检查</h2>
      <span class="tiny muted">运行每题「参考题解」核对题目本身，<b style="color:var(--txt)">不影响你的进度</b></span></div>
    <div id="queue" class="tiny muted">点击「自洽性检查」开始，或前往题面页单独检查。</div>
  </div>`;
  renderResMini();
  renderToolkitBox();
  $("#btnGenAll").onclick=async e=>{e.target.disabled=true;
    try{const r=await apiPost("/api/gen-all");toast(`已生成 ${r.count}/${r.total} 题 → dist/`);}
    catch(err){toast("生成失败: "+err.message);}finally{e.target.disabled=false;}};
  $("#btnCheckAll").onclick=runAllChecks;
  $("#btnReset").onclick=async()=>{
    if(!confirm("清空本机所有做题进度？\n（只删除 progress.json，不影响题目文件与 dist/）"))return;
    try{const r=await apiPost("/api/progress/reset",{confirm:true});
      PG=r.progress;paintProgress();toast("进度已清空");viewHome();}
    catch(err){toast("重置失败: "+err.message);}
  };
}

async function runAllChecks(){
  const box=$("#queue");const rows=[];let pass=0,fail=0;
  for(let i=0;i<CH.length;i++){
    const c=CH[i];
    box.innerHTML=`<div class="row tiny" style="justify-content:space-between">
      <span><span class="spin"></span> 正在检查 <b style="color:var(--txt)">${esc(c.name)}</b>
        (${i+1}/${CH.length})</span><span class="muted">PASS ${pass} · FAIL ${fail}</span></div>
      <div class="bar" style="margin:8px 0"><i style="width:${i*100/CH.length}%"></i></div>
      <div id="qrows" style="max-height:240px;overflow:auto"></div>`;
    let st="ERR",msg="",sec=0;
    try{const r=await apiPost("/api/check/"+c.name);st=r.status;msg=r.msg;sec=r.seconds;
      if(st==="PASS")pass++;else fail++;
    }catch(e){fail++;msg=e.message;}
    rows.unshift(`<div class="row" style="justify-content:space-between;padding:3px 0;
        border-bottom:1px solid rgba(34,48,77,.5)">
      <span>${st==="PASS"?'<span style="color:var(--ok)">✔</span>':'<span style="color:var(--err)">✘</span>'}
        <span class="mono">${esc(c.name)}</span></span>
      <span class="muted" style="font-size:.75rem">${st} · ${sec}s ${esc(msg||"")}</span></div>`);
    const qr=$("#qrows");if(qr)qr.innerHTML=rows.join("");
  }
  box.innerHTML=`<div class="row" style="justify-content:space-between">
      <span style="color:${fail?'var(--err)':'var(--ok)'};font-weight:600">
        ${fail?'检查完成 · 有问题':'题目全部自洽 🎉'} · PASS ${pass}/${CH.length}</span>
      <button class="btn sm" id="qclose">关闭</button></div>
    <div style="max-height:240px;overflow:auto;margin-top:8px">${rows.join("")}</div>
    <div class="tiny muted" style="margin-top:6px">这只是检查出题材料是否自洽，不计入做题进度。</div>`;
  const b=$("#qclose");if(b)b.onclick=()=>box.innerHTML="<span class='muted'>验证结束。</span>";
}

function renderResMini(){
  const el=$("#resMini");if(!el)return;
  if(!RES){el.innerHTML="<span class='muted tiny'>未探测</span>";return;}
  const items=[["John",RES.john],["rockyou",RES.rockyou],["hashcat",RES.hashcat],["7-Zip",RES.sevenzip]];
  el.innerHTML=items.map(([n,v])=>`<span class="tiny">
    ${v?'<span style="color:var(--ok)">✔</span>':'<span style="color:var(--err)">✘</span>'} ${n}</span>`).join("");
}

/* ---------------- 题目库 ---------------- */
let F={cat:"all",diff:"",q:"",sort:"def"};
function viewList(){
  setNav("ch");$("#crumb").textContent="题目库";
  $("#view").innerHTML=`
    <div class="row" style="margin-bottom:10px">
      <div class="search"><span class="ic">⌕</span>
        <input id="Q" placeholder="搜索题目 / 考点 / 分类…" value="${esc(F.q)}"></div>
      <select class="sel" id="SORT">
        <option value="def">默认排序</option><option value="pup">分值 ↑</option>
        <option value="pdn">分值 ↓</option><option value="name">名称</option></select>
      <select class="sel" id="DIFF"><option value="">全部难度</option>
        ${["入门","简单","中等","困难","专家"].map(d=>`<option>${d}</option>`).join("")}</select>
    </div>
    <div class="row" id="CATS" style="margin-bottom:14px;gap:6px"></div>
    <div class="cards" id="GRID"></div>`;
  $("#SORT").value=F.sort;$("#DIFF").value=F.diff;
  $("#Q").oninput=debounce(e=>{F.q=e.target.value;renderGrid();},120);
  $("#SORT").onchange=e=>{F.sort=e.target.value;renderGrid();};
  $("#DIFF").onchange=e=>{F.diff=e.target.value;renderGrid();};
  const cw=$("#CATS");
  const mk=(k,label)=>{const b=document.createElement("button");
    b.className="chip"+(F.cat===k?" on":"");b.textContent=label;b.dataset.k=k;
    b.onclick=()=>{F.cat=k;$$("#CATS .chip").forEach(x=>x.classList.toggle("on",x===b));renderGrid();};
    cw.appendChild(b);};
  mk("all",`全部 (${CH.length})`);
  CATS.forEach(cat=>{const n=CH.filter(c=>c.category===cat.k).length;
    if(n)mk(cat.k,`${cat.icon} ${cat.cn} (${n})`);});
  renderGrid();
}
function renderGrid(){
  const s=doneSet();const q=F.q.trim().toLowerCase();
  let list=CH.filter(c=>(F.cat==="all"||c.category===F.cat)
    &&(!F.diff||c.difficulty===F.diff)
    &&(!q||`${c.name} ${c.technique} ${c.description} ${c.category_cn} ${c.difficulty} ${c.points}`
        .toLowerCase().includes(q)));
  if(F.sort==="pup")list=[...list].sort((a,b)=>a.points-b.points);
  else if(F.sort==="pdn")list=[...list].sort((a,b)=>b.points-a.points);
  else if(F.sort==="name")list=[...list].sort((a,b)=>a.name.localeCompare(b.name));
  const g=$("#GRID");
  if(!list.length){g.innerHTML='<div class="empty" style="grid-column:1/-1"><div class="big">🔍</div>'
    +'没有匹配的题目<div class="tiny" style="margin-top:6px">试试清空搜索或切换分类</div></div>';return;}
  g.innerHTML=list.map(c=>`<a class="cc ${s.has(c.name)?"done":""}" href="#/c/${c.name}"
      style="--cat:${colorOf(c.category)}">
    <div class="hd"><span class="nm">${esc(c.name)}</span><span class="pt">${c.points}</span></div>
    <div class="row tiny" style="gap:6px">
      <span class="tag t-${c.difficulty}">${c.difficulty}</span>
      <span class="muted">${esc(c.category_cn)}</span>
      ${c.ready?"":'<span class="tag t-dim">未生成</span>'}
    </div>
    <div class="tech">${esc(c.technique)}</div>
    <div class="ft"><span>${c.hints_count} 条提示</span>
      <span style="margin-left:auto">打开题面 →</span></div>
  </a>`).join("");
}

/* ---------------- 题面页 ---------------- */
function viewChallenge(name){
  setNav("ch");
  const c=CH.find(x=>x.name===name);
  if(!c){$("#view").innerHTML='<div class="empty"><div class="big">404</div>题目不存在</div>';return;}
  $("#crumb").innerHTML=`<a href="#/challenges" style="color:var(--dim)">题目库</a>
    <span class="muted" style="margin:0 6px">/</span>${esc(c.name)}`;
  const order=CH.slice().sort((a,b)=>ORDER.indexOf(a.category)-ORDER.indexOf(b.category)||a.points-b.points);
  const oi=order.findIndex(x=>x.name===name);
  const prev=oi>0?order[oi-1]:null, next=oi>=0&&oi<order.length-1?order[oi+1]:null;
  const rec=recOf(name);
  $("#view").innerHTML=`
  <div class="card pad" style="margin-bottom:14px">
    <div class="row" style="justify-content:space-between;align-items:flex-start;gap:12px">
      <div style="min-width:0">
        <h1 style="font-size:1.32rem;margin-bottom:6px">${esc(c.name)}</h1>
        <div class="row tiny" style="gap:8px">
          <span class="tag t-${c.difficulty}">${c.difficulty}</span>
          <span class="muted">${esc(c.category_cn)}</span>
          <span style="color:var(--acc2);font-weight:700">${c.points} 分</span>
          <span class="muted">限时 ${c.timeout}s</span>
          ${c.requires.length?`<span class="muted">依赖: ${c.requires.map(esc).join(", ")}</span>`:""}
        </div>
      </div>
      <div id="STATUSCHIP" style="white-space:nowrap">${statusChip(name)}</div>
    </div>
    <div class="tiny muted" style="margin-top:8px">考点: ${esc(c.technique)}</div>
  </div>

  <div class="card pad" id="SUBMITCARD" style="margin-bottom:14px">
    <div class="row" style="justify-content:space-between;align-items:flex-start;gap:16px">
      <div style="flex:1 1 320px;min-width:260px">
        <h2 style="margin-bottom:4px">提交 flag</h2>
        <div class="tiny muted" style="line-height:1.7">
          算出 <span class="mono">flag{...}</span> 后填进来；<b style="color:var(--txt)">提交正确才算完成本题</b>。
          格式严格匹配（大小写敏感，全角括号会自动纠正）。
        </div>
        <div class="row" style="margin-top:10px;gap:8px;flex-wrap:nowrap">
          <input type="text" id="flagIn" class="flagin" placeholder="flag{...}"
                 autocomplete="off" autocapitalize="off" spellcheck="false">
          <button class="btn primary" id="bSubmit">提交</button>
        </div>
        <div id="SUBMITMSG" class="tiny" style="margin-top:8px;min-height:1.2em"></div>
      </div>
      <div style="min-width:168px;text-align:right;line-height:1.9" id="SUBMITSTATBOX">
        <div class="tiny muted">本题状态</div>
        <div class="tiny" style="color:${rec.solved?'var(--ok)':'var(--txt)'};font-weight:600">${rec.solved
          ? (rec.peeked?'已完成 · 看过答案':'已完成') : '未完成'}</div>
        <div class="tiny muted" style="margin-top:2px">提交次数 <b style="color:var(--txt)">${rec.attempts||0}</b></div>
        ${rec.solved_at?`<div class="tiny muted">完成于 ${esc(rec.solved_at)}</div>`:""}
      </div>
    </div>
  </div>

  <div class="tabs" id="TABS">
    <button data-t="desc" class="on">题目</button>
    <button data-t="hints">提示 (${c.hints_count})</button>
    <button data-t="wu">题解</button>
    <button data-t="run">自检</button>
  </div>

  <div class="pane on" id="P-desc">
    <div class="card pad" style="line-height:1.85;font-size:.95rem">${esc(c.description)}</div>
    <div class="actions" style="margin-top:14px">
      <button class="btn" id="bGen">📥 复制到 dist/</button>
      <button class="btn" id="bHint">💡 看提示</button>
      <button class="btn" id="bCheck">🔍 自检本题</button>
      <button class="btn ghost" id="bGiveUp">🔓 放弃并看答案</button>
    </div>
    <div class="res" id="R"></div>

    <div class="card pad" id="MATERIAL" style="margin-top:14px">
      <div class="row" style="justify-content:space-between;align-items:baseline;margin-bottom:4px">
        <h2>题目材料</h2>
        <span class="tiny muted" id="MATMETA"></span>
      </div>
      <div class="tiny muted" style="margin-bottom:10px">
        材料已随题目直接展开在本页，无需另开窗口或去别的站点。
      </div>
      <div id="MATBODY"><div class="row tiny muted"><span class="spin"></span> 加载材料…</div></div>
    </div>
  </div>

  <div class="pane" id="P-hints">
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <h2>分步提示</h2>
        <button class="btn sm" id="bNextHint">显示下一条</button></div>
      <div id="HINTS" style="margin-top:12px"></div>
      <div class="tiny muted" style="margin-top:10px">提示逐条揭示，避免剧透。</div>
    </div>
  </div>

  <div class="pane" id="P-wu"><div class="card" id="WU"><span class="muted">加载题解…</span></div></div>

  <div class="pane" id="P-run">
    <div class="card pad" style="margin-bottom:12px">
      <h2 style="margin-bottom:6px">验证参考题解</h2>
      <div class="tiny muted" style="line-height:1.85">
        「验证」只确认题目材料与参考题解自洽，<b style="color:var(--txt)">与你的做题进度无关</b>：<br>
        ① 把 <span class="mono">src/</span> 附件复制到实例目录
        <span class="mono">instances/verify/${esc(c.name)}/</span><br>
        ② 在该目录运行参考题解 <span class="mono">solution/solve.py</span><br>
        ③ 从输出提取 <span class="mono">flag{...}</span> 并与标准答案逐字比对
      </div>
      <div class="actions" style="margin-top:14px">
        <button class="btn primary" id="bRun">▶ 开始验证</button>
        <label class="row tiny" style="gap:6px;cursor:pointer">
          <input type="checkbox" id="keepInst" style="width:15px;height:15px;accent-color:var(--acc)">
          保留实例（不删除，可查看现场）</label>
        <button class="btn" id="bScript">👁 查看参考脚本</button>
        <button class="btn" id="bReveal" style="display:none">📂 打开实例目录</button>
      </div>
      <div id="VERIFY"></div>
      <div id="SCRIPTBOX"></div>
    </div>
    <div class="card pad" id="SERVERCARD"></div>
  </div>

  <div class="row" style="justify-content:space-between;margin-top:18px">
    <div>${prev?`<a class="btn sm" href="#/c/${prev.name}">← ${esc(prev.name)}</a>`:""}</div>
    <div>${next?`<a class="btn sm" href="#/c/${next.name}">${esc(next.name)} →</a>`:""}</div>
  </div>`;

  /* ---- 提交 flag：本题「完成」的唯一入口 ---- */
  const inp=$("#flagIn"), msg=$("#SUBMITMSG"), sbtn=$("#bSubmit");
  function paintSubmit(){
    const r=recOf(name);
    $("#STATUSCHIP").innerHTML=statusChip(name);
    $("#SUBMITSTATBOX").innerHTML=`
      <div class="tiny muted">本题状态</div>
      <div class="tiny" style="color:${r.solved?'var(--ok)':'var(--txt)'};font-weight:600">
        ${r.solved?(r.peeked?'已完成 · 看过答案':'已完成'):'未完成'}</div>
      <div class="tiny muted" style="margin-top:2px">提交次数 <b style="color:var(--txt)">${r.attempts||0}</b></div>
      ${r.solved_at?`<div class="tiny muted">完成于 ${esc(r.solved_at)}</div>`:""}`;
  }
  let submitting=false;
  async function doSubmit(){
    if(submitting)return;
    submitting=true;sbtn.disabled=true;
    msg.innerHTML='<span class="muted">判定中…</span>';
    try{
      const r=await apiPost("/api/submit/"+name,{flag:inp.value});
      PG=r.progress||PG;paintProgress();
      if(r.correct){
        inp.classList.remove("bad");inp.classList.add("ok");
        msg.innerHTML='<span style="color:var(--ok);font-weight:600">✔ flag 正确</span>'
          +(r.first?' <span style="color:var(--acc2);font-weight:700">+'+r.awarded+' 分</span>'
                   :' <span class="muted">（此前已完成，不重复计分）</span>')
          +(r.peeked?' <span class="muted">· 本题看过答案，不计入「独立解出」</span>':"");
        toast(r.first?"✔ 答对了！+"+r.awarded+" 分":"✔ 这题你已经完成过了");
        $("#SUBMITCARD").style.borderColor="rgba(52,211,153,.45)";
      }else{
        inp.classList.remove("ok");inp.classList.add("bad");
        msg.innerHTML='<span style="color:var(--err);font-weight:600">✘ '+esc(r.message||"flag 不正确")+'</span>'
          +' <span class="muted">· 已提交 '+r.attempts+' 次</span>';
        $("#SUBMITCARD").style.borderColor="";
        inp.select();
      }
      paintSubmit();
    }catch(e){
      msg.innerHTML='<span style="color:var(--err)">请求失败: '+esc(e.message)+'</span>';
    }finally{submitting=false;sbtn.disabled=false;}
  }
  sbtn.onclick=doSubmit;
  inp.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();doSubmit();}});
  inp.addEventListener("input",()=>inp.classList.remove("bad","ok"));

  /* ---- 放弃：给答案但只打「看过答案」标记，不算完成 ---- */
  $("#bGiveUp").onclick=async()=>{
    if(!confirm("这会显示本题的标准答案，并在进度里标记「看过答案」。\n"
      + "本题之后仍可提交完成，但不再计入「独立解出」。\n\n确定要看吗？"))return;
    try{
      const r=await apiPost("/api/giveup/"+name);
      PG=r.progress||PG;paintProgress();
      const box=$("#R");box.className="res on";box.style.display="block";
      box.innerHTML='<div class="hd"><span class="verdict ok">🔓 '+esc(r.flag)+'</span></div>'
        +'<div class="tiny muted">已标记「看过答案」——把它填到上方提交框即可记为完成。</div>';
      paintSubmit();
    }catch(e){toast("读取失败: "+e.message);}
  };

  $$("#TABS button").forEach(b=>b.onclick=()=>{
    $$("#TABS button").forEach(x=>x.classList.toggle("on",x===b));
    $$(".pane").forEach(p=>p.classList.toggle("on",p.id==="P-"+b.dataset.t));
    if(b.dataset.t==="wu")loadWu();
    if(b.dataset.t==="hints")loadHints();
  });
  $("#bHint").onclick=()=>$$("#TABS button")[1].click();
  $("#bCheck").onclick=()=>$$("#TABS button")[3].click();

  /* ---- 验证: 展示完整过程 (实例目录 / 命令 / 输出 / 比对) ---- */
  let lastInst=null;
  $("#bReveal").onclick=async()=>{
    if(!lastInst)return;
    try{await apiPost("/api/reveal",{path:lastInst});toast("已在文件管理器中打开");}
    catch(e){toast("打开失败: "+e.message);}
  };

  $("#bRun").onclick=async e=>{
    const btn=e.target,box=$("#VERIFY"),keep=$("#keepInst").checked;
    btn.disabled=true;
    box.innerHTML='<div class="steps2"><div class="st"><span class="spin"></span> 正在创建实例并运行参考题解…</div></div>';
    try{
      const r=await apiPost("/api/verify/"+name,{keep});
      lastInst=r.instance;
      if(r.instance)$("#bReveal").style.display="";
      const rows=(r.steps||[]).map(s=>'<div class="st '+s.status+'">'
          +'<span class="sn">'+s.n+'</span>'
          +'<span class="sb"><b>'+esc(s.title)+'</b>'
          +(s.detail?'<span class="sd">'+esc(s.detail)+'</span>':'')
          +'</span></div>').join("");
      const out=r.stdout||"",err=r.stderr||"";
      const pass=r.pass;
      box.innerHTML='<div class="vres '+(pass?"ok":"bad")+'">'
          +'<span class="vbadge">'+(pass?"✔ PASS":"✘ "+(r.flag?"FAIL":"NO FLAG"))+'</span>'
          +'<span class="tiny">耗时 '+r.seconds+'s · 实例'+(r.kept?"已保留":"已清理")+'</span></div>'
        +'<div class="steps2">'+rows+'</div>'
        +((out||err)?'<details class="io" open><summary>脚本输出 (stdout '+out.length+'B / stderr '+err.length+'B)</summary>'
          +'<pre class="code short">'+esc(out||"(空)")+(err?"\n--- stderr ---\n"+esc(err):"")+'</pre></details>':"")
        +(r.instance?'<div class="tiny muted" style="margin-top:10px">实例目录: <span class="mono">'
          +esc(r.instance)+'</span></div>':"");
      /* 自检只说明「题目材料与参考题解自洽」，不改动做题进度 */
    }catch(err){
      box.innerHTML='<div class="vres bad"><span class="vbadge">✘ 请求失败</span>'
        +'<span class="tiny">'+esc(err.message)+'</span></div>';
    }finally{btn.disabled=false;}
  };

  /* ---- 参考脚本 (剧透确认) ---- */
  let scriptShown=false;
  $("#bScript").onclick=async()=>{
    const box=$("#SCRIPTBOX");
    if(scriptShown){box.innerHTML="";scriptShown=false;return;}
    if(!confirm("查看参考题解脚本会剧透本题解法。\n确定要看吗？"))return;
    try{
      const r=await apiGet("/api/script/"+name);
      box.innerHTML='<div class="card" style="margin-top:12px;background:var(--panel2)">'
        +'<div class="row" style="justify-content:space-between">'
        +'<b class="mono" style="font-size:.85rem">'+esc(r.path)+'</b>'
        +'<button class="copy" id="cpScript">复制</button></div>'
        +'<pre class="code">'+esc(r.text)+'</pre>'
        +'<div class="tiny muted">这是本题的参考题解 —— 看完请自己再写一遍。</div></div>';
      $("#cpScript").onclick=()=>copyText(r.text);
      scriptShown=true;
    }catch(e){toast("读取失败: "+e.message);}
  };

  /* ---- 服务实例 (仅 server.py 题) / oracle 说明 ---- */
  const sc=$("#SERVERCARD");
  if(c.server){
    sc.innerHTML='<div class="row" style="justify-content:space-between;align-items:flex-start">'
      +'<div><h2>启动题目服务</h2>'
      +'<div class="tiny muted" style="margin-top:4px;line-height:1.75">'
      +'本题附带 <span class="mono">'+esc(c.server_script)+'</span>（网络服务）。启动后分配本机端口，'
      +'可用 nc / Python / 任意客户端手动攻击 —— 与「验证参考题解」是两件事。</div></div>'
      +'<button class="btn primary" id="bStartSrv">▶ 启动实例</button></div>'
      +'<div id="SRV" style="margin-top:12px"></div>';
    $("#bStartSrv").onclick=async e=>{
      const btn=e.target;btn.disabled=true;btn.textContent="启动中…";
      try{
        const r=await apiPost("/api/instance/"+name+"/start");
        if(!r.ok)throw new Error(r.error||"启动失败");
        const py="python -c \"import socket;socket.create_connection(('127.0.0.1',"
          +r.port+")).recv(4096)\"";
        $("#SRV").innerHTML='<div class="vres ok"><span class="vbadge">✔ 运行中</span>'
            +'<span class="tiny">端口 '+r.port+' · READY: <span class="mono">'+esc(r.ready)+'</span></span></div>'
          +'<dl class="kvgrid"><dt>实例目录</dt><dd>'+esc(r.instance)+'</dd>'
          +'<dt>启动命令</dt><dd>'+esc(r.cmd)+'</dd>'
          +'<dt>连接方式</dt><dd>nc 127.0.0.1 '+r.port+' ／ '+esc(py)+'</dd></dl>'
          +'<div class="actions"><button class="btn sm" id="bStopSrv">■ 停止实例</button>'
          +'<button class="btn sm" id="bRevSrv">📂 打开实例目录</button></div>';
        $("#bStopSrv").onclick=async ev=>{
          ev.target.disabled=true;
          try{await apiPost("/api/instance/"+name+"/stop");toast("实例已停止");}
          catch(err){toast("停止失败: "+err.message);}
          $("#SRV").innerHTML='<div class="tiny muted">实例已停止。</div>';
        };
        $("#bRevSrv").onclick=async()=>{
          try{await apiPost("/api/reveal",{path:r.instance});}
          catch(err){toast("打开失败: "+err.message);}
        };
      }catch(err){
        $("#SRV").innerHTML='<div class="vres bad"><span class="vbadge">✘ 启动失败</span>'
          +'<span class="tiny">'+esc(err.message)+'</span></div>';
      }finally{btn.disabled=false;btn.textContent="▶ 启动实例";}
    };
  }else if(c.oracle){
    sc.innerHTML='<h2>本地预言机 / 工具脚本</h2>'
      +'<div class="tiny muted" style="margin-top:6px;line-height:1.8">'
      +'本题附带 <span class="mono">oracle.py</span>（stdin/stdout 交互，不监听端口）。'
      +'材料已在上方展开；复制到 dist/ 后可在终端运行它并按提示输入：</div>'
      +'<pre class="code short" style="margin-top:10px">'+esc(c.run_hint||"")+'</pre>';
  }else{
    sc.innerHTML='<span class="tiny muted">本题是无服务端的离线题：附件即全部输入，直接分析即可。</span>';
  }


  async function gen(btn){
    if(btn)btn.disabled=true;
    try{const r=await apiPost("/api/gen/"+name);toast("已复制到 "+r.dest);loadMaterial();}
    catch(err){toast("复制失败: "+err.message);}
    finally{if(btn)btn.disabled=false;}
  }
  $("#bGen").onclick=e=>gen(e.target);

  /* ---- 题目材料：直接内联展开，不用另开窗口 ---- */
  async function loadMaterial(){
    const body=$("#MATBODY"), meta=$("#MATMETA");
    let r;
    try{r=await apiGet("/api/material/"+name);}
    catch(err){
      body.innerHTML='<span class="tiny" style="color:var(--err)">材料读取失败: '+esc(err.message)+'</span>';
      return;
    }
    const files=r.files||[];
    if(!files.length){
      body.innerHTML='<span class="muted tiny">本题没有附件 —— 描述即全部信息。</span>';
      meta.textContent="";return;
    }
    meta.innerHTML=esc(r.dir)+' · '+files.length+' 个文件'
      +(r.gen?' · <span style="color:var(--ok)">已复制到 dist/</span>':'');
    body.innerHTML=files.map((f,i)=>{
      const url='/api/download/'+encodeURIComponent(name)+'/'+encodeURIComponent(f.name);
      const dl='<a class="copy" href="'+url+'" download>下载</a>';
      const head='<div class="mat-hd"><b class="mono">'+esc(f.name)+'</b>'
        +'<span class="tiny muted">'+fmtB(f.size)
        +(f.binary?' · 二进制':' · '+(f.lines||0)+' 行')+'</span>'
        +'<span style="margin-left:auto">'+(f.binary?'':(''+
          '<button class="copy" data-cp="'+i+'">复制</button> '))+dl+'</span></div>';
      if(f.binary){
        if(/\.(png|jpe?g|gif|webp|bmp)$/i.test(f.name)){
          return '<div class="mat">'+head
            +'<img src="'+url+'" style="max-width:100%;border-radius:10px;border:1px solid var(--line)">'
            +'</div>';
        }
        return '<div class="mat">'+head
          +'<div class="tiny muted">二进制文件，下载后本地分析。</div></div>';
      }
      return '<div class="mat">'+head
        +'<pre class="code" id="matpre'+i+'">'+esc(f.text||"")+'</pre></div>';
    }).join("");
    $$('#MATBODY button[data-cp]').forEach(b=>b.onclick=()=>{
      const f=files[+b.dataset.cp];copyText(f.text||"");
    });
  }

  let hints=null,shown=0;
  async function loadHints(){
    if(hints===null){const r=await apiGet("/api/hints/"+name);hints=r.hints||[];}
    if(shown===0&&hints.length)shown=1;
    renderHints();
  }
  function renderHints(){
    $("#HINTS").innerHTML=hints&&hints.length?hints.slice(0,shown).map((h,i)=>
      `<div class="card" style="margin-bottom:8px;background:var(--panel2)">
        <div class="tiny" style="color:var(--warn);font-weight:600">提示 ${i+1}</div>
        <div style="margin-top:4px;font-size:.9rem">${esc(h)}</div></div>`).join("")
      :'<span class="muted">本题没有提示</span>';
    $("#bNextHint").style.display=(!hints||shown>=hints.length)?"none":"";
  }
  $("#bNextHint").onclick=()=>{if(hints&&shown<hints.length)shown++;renderHints();};

  let wuLoaded=false;
  async function loadWu(){
    if(wuLoaded)return;wuLoaded=true;
    const r=await apiGet("/api/writeup/"+name);
    $("#WU").innerHTML=r.writeup?md(r.writeup):'<span class="muted">暂无题解</span>';
  }

  loadMaterial();
}

/* ---------------- 资源页 ---------------- */
async function viewRes(){
  setNav("res");$("#crumb").textContent="资源探测";
  $("#view").innerHTML='<div class="empty"><span class="spin"></span> 探测中…</div>';
  try{RES=await apiGet("/api/resources");}catch(e){}
  const r=RES||{};
  const rows=[
    ["John the Ripper", r.john, r.john?r.john.version:"", r.john?r.john.exe:""],
    ["rockyou.txt", r.rockyou, r.rockyou&&r.rockyou.lines?(r.rockyou.lines.toLocaleString()+" 行"):"",
     r.rockyou?r.rockyou.path:""],
    ["hashcat", r.hashcat, "", r.hashcat?r.hashcat.exe:""],
    ["7-Zip", r.sevenzip, "", r.sevenzip?r.sevenzip.exe:""],
  ];
  const deps=CH.filter(c=>c.requires.length);
  $("#view").innerHTML=`
    <div class="card pad" style="margin-bottom:14px">
      <h1 style="font-size:1.2rem;margin-bottom:4px">🩺 外部资源</h1>
      <div class="tiny muted">由 <span class="mono">python ctf.py doctor</span> 扫描并缓存
        (${esc(r.scanned_at||"未扫描")}) · 扫描根: ${(r.roots||[]).map(esc).join(", ")||"—"}</div>
      <div style="overflow-x:auto;margin-top:14px"><table class="tb">
        <thead><tr><th>工具 / 字典</th><th>状态</th><th>版本 / 规模</th><th>路径</th></tr></thead>
        <tbody>${rows.map(([n,v,ver,p])=>`<tr>
          <td><b>${n}</b></td>
          <td>${v?'<span style="color:var(--ok)">✔ 已找到</span>':'<span style="color:var(--err)">✘ 未找到</span>'}</td>
          <td class="muted">${esc(ver||"—")}</td>
          <td class="mono tiny" style="word-break:break-all">${esc(p||"—")}</td></tr>`).join("")}
        </tbody></table></div>
    </div>
    <div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2>题目依赖</h2><span class="tiny muted">${deps.length} 题声明了外部依赖</span></div>
      <div style="overflow-x:auto"><table class="tb">
        <thead><tr><th>题目</th><th>需要</th><th>状态</th></tr></thead><tbody>
      ${deps.map(c=>{const miss=c.requires.filter(k=>!r[k]);
        return `<tr><td><a href="#/c/${c.name}">${esc(c.name)}</a></td>
          <td class="mono tiny">${c.requires.map(esc).join(", ")}</td>
          <td>${miss.length?`<span style="color:var(--err)">缺 ${miss.map(esc).join(", ")}</span>`
            :'<span style="color:var(--ok)">✔ 可解</span>'}</td></tr>`;}).join("")}
      </tbody></table></div>
      <div class="tiny muted" style="margin-top:12px">重新扫描 CLI:
        <span class="mono">python ctf.py doctor --rescan</span></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2>密码工具箱</h2>
        <button class="btn sm" id="tkRecheck">↻ 重新探测</button></div>
      <div class="tiny muted tk-box" style="line-height:1.8">探测中…</div>
    </div>`;
  renderToolkitBox();
  $("#tkRecheck").onclick=e=>{e.target.disabled=true;loadToolkit().finally(()=>{e.target.disabled=false;});};
}

/* ---------------- 路由 ---------------- */
const ORDER=["classical","symmetric","stream","rsa","pubkey","hash","lattice","cracking"];
function route(){
  const h=location.hash.replace(/^#/,"")||"/";
  if(h.startsWith("/c/")){viewChallenge(decodeURIComponent(h.slice(3)));return;}
  if(h.startsWith("/challenges")){viewList();return;}
  if(h.startsWith("/resources")){viewRes();return;}
  viewHome();
  window.scrollTo({top:0});
}
window.addEventListener("hashchange",route);

async function boot(){
  try{
    const d=await apiGet("/api/index");
    CH=d.challenges;
    (d.cats||[]).forEach(c=>{CATS.push(c);CIB[c.k]=c;});
    const bv=$("#brandVer");if(bv)bv.textContent="v"+(d.version||"?");
  }catch(e){
    $("#view").innerHTML='<div class="empty"><div class="big">⚠</div>无法加载题目索引<br>'
      +'<span class="tiny">'+esc(e.message)+'</span></div>';return;
  }
  await refreshProgress();
  await loadToolkit();
  try{RES=await apiGet("/api/resources");}catch(e){}
  route();
}
document.addEventListener("keydown",e=>{
  if(e.key==="/"&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)){
    const q=$("#Q");if(q){e.preventDefault();q.focus();}}
  if(e.key==="Escape"&&document.activeElement&&/INPUT|TEXTAREA/.test(document.activeElement.tagName))
    document.activeElement.blur();
});
boot();
</script>
</body>
</html>
"""

PAGE = PAGE_RAW.replace("__CSS__", BASE_CSS).replace("__JS__", JS_HELPERS)


def serve(port=8787, quiet=False, toolkit_port=None):
    global TOOLKIT_PORT
    TOOLKIT_PORT = toolkit_port
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
