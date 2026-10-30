# -*- coding: utf-8 -*-
"""
webbase.py — Web 控制台与工具箱共用的设计系统 (CSS + JS 基础库)

两个界面 (webconsole 题目站 / toolkit_web 工具箱) 共用本模块的 BASE_CSS 与
JS_HELPERS, 保证视觉与交互一致: 深色主题、侧边栏、卡片、标签页、结果面板、Toast。
"""

BASE_CSS = r"""
:root{
  --bg:#080c14; --bg2:#0d1320; --panel:#121a2a; --panel2:#172032; --line:#22304d;
  --line2:#2c3d61; --txt:#dde5f5; --dim:#8496b8; --dim2:#5f7093;
  --acc:#22d3ee; --acc2:#a78bfa; --ok:#34d399; --warn:#fbbf24; --err:#f87171;
  --r:14px; --r2:10px;
  --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,"Courier New",monospace;
  --sans:"Segoe UI",system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-text-size-adjust:100%}
body{background:
  radial-gradient(1100px 480px at 82% -12%, #16263f 0%, transparent 62%),
  radial-gradient(900px 420px at -8% 108%, #1c1638 0%, transparent 58%), var(--bg);
  color:var(--txt);font-family:var(--sans);min-height:100vh;line-height:1.6}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}
::selection{background:rgba(34,211,238,.28)}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#243350;border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#31456b}
::-webkit-scrollbar-track{background:transparent}

/* ---------- 布局 ---------- */
.shell{display:flex;min-height:100vh}
.side{width:236px;flex:0 0 236px;border-right:1px solid var(--line);
  background:rgba(10,15,24,.72);backdrop-filter:blur(8px);position:sticky;top:0;height:100vh;
  display:flex;flex-direction:column;padding:16px 12px;gap:6px;overflow-y:auto}
.brand{display:flex;align-items:center;gap:9px;padding:6px 10px 16px;font-weight:700;font-size:1.02rem;letter-spacing:.3px}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--acc);box-shadow:0 0 12px var(--acc)}
.brand small{color:var(--dim2);font-weight:400;font-size:.68rem;display:block;letter-spacing:0}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:9px;padding:9px 11px;border-radius:var(--r2);
  color:var(--dim);font-size:.9rem;text-decoration:none;transition:.15s;border:1px solid transparent}
.nav a:hover{background:var(--panel);color:var(--txt);text-decoration:none}
.nav a.on{background:linear-gradient(90deg,rgba(34,211,238,.16),rgba(167,139,250,.12));
  color:var(--txt);border-color:var(--line2)}
.nav a .ic{width:18px;text-align:center;font-size:.95rem}
.nav .grp{font-size:.68rem;letter-spacing:.12em;color:var(--dim2);padding:14px 11px 5px;text-transform:uppercase}
.side .foot{margin-top:auto;padding:10px;color:var(--dim2);font-size:.72rem;line-height:1.5}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:12px;
  padding:12px 22px;background:rgba(8,12,20,.84);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--line)}
.topbar .title{font-size:.98rem;font-weight:600}
.topbar .sp{flex:1}
.page{padding:22px;max-width:1280px;width:100%;margin:0 auto}

/* ---------- 通用组件 ---------- */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--r2);
  border:1px solid var(--line2);background:var(--panel2);color:var(--txt);cursor:pointer;
  font-size:.88rem;font-family:inherit;transition:.15s;white-space:nowrap}
.btn:hover{border-color:var(--acc);color:var(--acc);text-decoration:none}
.btn.primary{background:linear-gradient(90deg,rgba(34,211,238,.22),rgba(167,139,250,.22));border-color:var(--acc)}
.btn.ghost{background:transparent}
.btn.sm{padding:5px 10px;font-size:.8rem}
.btn:disabled{opacity:.5;cursor:progress}
.chip{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:99px;
  border:1px solid var(--line2);background:transparent;color:var(--dim);cursor:pointer;
  font-size:.83rem;font-family:inherit;transition:.15s}
.chip:hover{color:var(--txt);border-color:var(--acc)}
.chip.on{background:linear-gradient(90deg,rgba(34,211,238,.18),rgba(167,139,250,.18));
  color:var(--txt);border-color:var(--acc)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px}
.card.pad{padding:18px 20px}
.tag{display:inline-block;font-size:.72rem;padding:2px 9px;border-radius:99px;font-weight:600;letter-spacing:.2px}
.t-入门{background:rgba(52,211,153,.15);color:var(--ok)}
.t-简单{background:rgba(34,211,238,.15);color:var(--acc)}
.t-中等{background:rgba(251,191,36,.15);color:var(--warn)}
.t-困难{background:rgba(251,146,60,.18);color:#fb923c}
.t-专家{background:rgba(248,113,113,.18);color:var(--err)}
.t-dim{background:rgba(132,150,184,.14);color:var(--dim)}
.muted{color:var(--dim)}
.tiny{font-size:.78rem}
.mono{font-family:var(--mono)}
h1{font-size:1.5rem;line-height:1.3}
h2{font-size:1.05rem}
h3{font-size:.95rem}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.grid{display:grid;gap:12px}
.search{position:relative;flex:1 1 240px;max-width:420px}
.search input{width:100%;padding:9px 14px 9px 34px;border-radius:var(--r2);
  border:1px solid var(--line2);background:var(--panel);color:var(--txt);
  outline:none;font-size:.9rem;font-family:inherit}
.search input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(34,211,238,.12)}
.search .ic{position:absolute;left:11px;top:8px;color:var(--dim2)}
select,input[type=text],input[type=number],textarea{font-family:inherit}
.sel{background:var(--panel);border:1px solid var(--line2);color:var(--txt);
  border-radius:var(--r2);padding:8px 10px;font-size:.86rem;outline:none}
.sel:focus{border-color:var(--acc)}
progress{width:120px;height:7px;border-radius:99px;overflow:hidden;border:none;background:var(--panel2)}
progress::-webkit-progress-bar{background:var(--panel2);border-radius:99px}
progress::-webkit-progress-value{background:linear-gradient(90deg,var(--acc),var(--acc2));border-radius:99px}
.bar{height:7px;border-radius:99px;background:var(--panel2);overflow:hidden}
.bar>i{display:block;height:100%;border-radius:99px;
  background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .4s}

/* ---------- 卡片墙 ---------- */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(272px,1fr));gap:12px}
.cc{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:13px 15px;cursor:pointer;transition:.16s;display:flex;flex-direction:column;gap:8px;
  overflow:hidden;text-decoration:none;color:inherit}
.cc:hover{transform:translateY(-2px);border-color:var(--acc);box-shadow:0 10px 26px rgba(0,0,0,.42);text-decoration:none}
.cc::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--cat,var(--acc))}
.cc.done{opacity:.66}
.cc .hd{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.cc .nm{font-weight:600;font-size:.96rem}
.cc .pt{color:var(--acc2);font-weight:700;font-size:.88rem}
.cc .tech{color:var(--dim);font-size:.8rem;flex:1}
.cc .ft{display:flex;align-items:center;gap:8px;font-size:.76rem;color:var(--dim2)}
.cc .st{font-size:.95rem}
.cc.done .nm::after{content:" ✓";color:var(--ok)}

/* ---------- 标签页 ---------- */
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:14px 0 16px;overflow-x:auto}
.tabs button{background:none;border:none;border-bottom:2px solid transparent;color:var(--dim);
  padding:10px 14px;cursor:pointer;font-size:.88rem;font-family:inherit;white-space:nowrap}
.tabs button:hover{color:var(--txt)}
.tabs button.on{color:var(--acc);border-bottom-color:var(--acc)}
.pane{display:none}
.pane.on{display:block;animation:fade .18s ease}
@keyframes fade{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}

/* ---------- 文本块 ---------- */
pre.code{background:#070b12;border:1px solid var(--line);border-radius:var(--r2);
  padding:12px 14px;overflow:auto;font-size:.8rem;font-family:var(--mono);
  line-height:1.55;max-height:52vh;white-space:pre-wrap;word-break:break-all}
pre.code.short{max-height:none}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 14px;font-size:.86rem}
.kv dt{color:var(--dim)}
.kv dd{font-family:var(--mono);word-break:break-all}
.md{font-size:.92rem;line-height:1.75}
.md h3{color:var(--acc);margin:1rem 0 .4rem;font-size:.98rem}
.md h4{color:var(--acc2);margin:.9rem 0 .35rem;font-size:.92rem}
.md p{margin:.45rem 0}
.md ul,.md ol{margin:.4rem 0 .4rem 1.35rem}
.md li{margin:.18rem 0}
.md code{background:#070b12;border:1px solid var(--line);border-radius:5px;
  padding:.06rem .35rem;font-size:.86em;font-family:var(--mono)}
.md pre{background:#070b12;border:1px solid var(--line);border-radius:var(--r2);
  padding:11px 13px;overflow:auto;margin:.55rem 0}
.md pre code{border:none;background:none;padding:0}
.md blockquote{border-left:3px solid var(--acc2);padding:.1rem 0 .1rem .8rem;color:var(--dim);margin:.5rem 0}
.md strong{color:#fff}

/* ---------- 表单 (工具箱) ---------- */
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.field label{font-size:.83rem;color:var(--dim);display:flex;gap:6px;align-items:baseline}
.field label b{color:var(--txt);font-weight:600;font-size:.87rem}
.field label span{color:var(--dim2);font-size:.76rem;font-weight:400}
.field input[type=text],.field input[type=number],.field textarea,.field select{
  background:#0b111c;border:1px solid var(--line2);color:var(--txt);border-radius:var(--r2);
  padding:9px 12px;font-size:.88rem;outline:none;font-family:var(--mono);width:100%}
.field textarea{min-height:88px;resize:vertical;line-height:1.5}
.field input:focus,.field textarea:focus,.field select:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(34,211,238,.1)}
.field .hint{font-size:.75rem;color:var(--dim2)}
.field.inline{flex-direction:row;align-items:center;gap:9px}
.field.inline input[type=checkbox]{width:16px;height:16px;accent-color:var(--acc)}
.actions{display:flex;gap:9px;align-items:center;margin-top:4px;flex-wrap:wrap}
.res{margin-top:16px;display:none}
.res.on{display:block}
.res .hd{display:flex;align-items:center;gap:9px;margin-bottom:8px}
.res .verdict{font-weight:700}
.res .verdict.ok{color:var(--ok)}
.res .verdict.bad{color:var(--err)}
.steps{margin-top:10px;font-size:.8rem;color:var(--dim)}
.steps summary{cursor:pointer;color:var(--dim2)}
.steps ol{margin:.4rem 0 0 1.2rem;font-family:var(--mono);font-size:.78rem;line-height:1.6}
.copy{background:none;border:1px solid var(--line2);color:var(--dim);border-radius:6px;
  padding:2px 7px;font-size:.72rem;cursor:pointer;font-family:inherit}
.copy:hover{color:var(--acc);border-color:var(--acc)}

/* ---------- 工具列表 ---------- */
.tools{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}
.tool{background:var(--panel);border:1px solid var(--line);border-radius:var(--r2);
  padding:12px 14px;cursor:pointer;transition:.15s}
.tool:hover{border-color:var(--acc);transform:translateY(-1px)}
.tool b{display:block;font-size:.9rem;margin-bottom:3px}
.tool span{font-size:.76rem;color:var(--dim);display:block;line-height:1.45}
.tool.on{border-color:var(--acc);background:linear-gradient(135deg,rgba(34,211,238,.1),rgba(167,139,250,.08))}

/* ---------- 验证过程时间线 ---------- */
.vres{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:var(--r2);
  margin:14px 0 10px;border:1px solid var(--line2);background:var(--panel2)}
.vres.ok{border-color:rgba(52,211,153,.45);background:rgba(52,211,153,.08)}
.vres.bad{border-color:rgba(248,113,113,.45);background:rgba(248,113,113,.08)}
.vbadge{font-weight:700;font-size:.86rem}
.vres.ok .vbadge{color:var(--ok)}
.vres.bad .vbadge{color:var(--err)}
.steps2{display:flex;flex-direction:column;gap:2px;margin-top:6px}
.steps2 .st{display:flex;gap:11px;padding:7px 2px;border-bottom:1px solid rgba(34,48,77,.5)}
.steps2 .st:last-child{border-bottom:none}
.steps2 .sn{flex:0 0 22px;height:22px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:.72rem;font-weight:700;background:var(--panel2);
  border:1px solid var(--line2);color:var(--dim)}
.steps2 .st.ok .sn{border-color:rgba(52,211,153,.6);color:var(--ok);background:rgba(52,211,153,.1)}
.steps2 .st.fail .sn{border-color:rgba(248,113,113,.6);color:var(--err);background:rgba(248,113,113,.1)}
.steps2 .sb{min-width:0;flex:1;font-size:.85rem;display:flex;flex-direction:column;gap:2px}
.steps2 .sb b{font-weight:600}
.steps2 .st.ok .sb b{color:var(--ok)}
.steps2 .st.fail .sb b{color:var(--err)}
.steps2 .sd{font-family:var(--mono);font-size:.76rem;color:var(--dim);
  white-space:pre-wrap;word-break:break-all}
details.io{margin-top:12px}
details.io summary{cursor:pointer;font-size:.8rem;color:var(--dim2);padding:4px 0}
details.io summary:hover{color:var(--acc)}
details.io pre{margin-top:6px}

/* ---------- Toast / 空态 / 表格 ---------- */
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(8px);
  background:var(--panel2);border:1px solid var(--acc);color:var(--txt);
  padding:10px 18px;border-radius:var(--r2);opacity:0;transition:.25s;z-index:99;
  pointer-events:none;font-size:.86rem;box-shadow:0 12px 34px rgba(0,0,0,.5);max-width:80vw}
#toast.show{opacity:1;transform:translateX(-50%)}
.empty{text-align:center;color:var(--dim);padding:3rem 1rem}
.empty .big{font-size:2.2rem;margin-bottom:.5rem;opacity:.8}
table.tb{width:100%;border-collapse:collapse;font-size:.86rem}
table.tb th{text-align:left;color:var(--dim);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--line)}
table.tb td{padding:8px 10px;border-bottom:1px solid rgba(34,48,77,.55);vertical-align:top}
table.tb tr:last-child td{border-bottom:none}
table.tb tr:hover td{background:rgba(34,211,238,.04)}
.spin{width:15px;height:15px;border:2px solid rgba(34,211,238,.28);border-top-color:var(--acc);
  border-radius:50%;display:inline-block;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}

/* ---------- 响应式 ---------- */
@media (max-width:960px){
  .shell{flex-direction:column}
  .side{width:100%;flex:none;height:auto;position:sticky;top:0;z-index:40;
    flex-direction:row;align-items:center;gap:4px;padding:8px 10px;overflow-x:auto;
    border-right:none;border-bottom:1px solid var(--line)}
  .brand{padding:0 10px 0 4px;font-size:.92rem;white-space:nowrap}
  .brand small{display:none}
  .nav{flex-direction:row;gap:2px}
  .nav .grp{display:none}
  .nav a{padding:7px 10px;font-size:.83rem;white-space:nowrap}
  .nav a span.tx{display:none}
  .nav a .ic{width:auto}
  .side .foot{display:none}
  .page{padding:14px}
  .topbar{padding:10px 14px}
  .cards{grid-template-columns:1fr}
  .kv{grid-template-columns:1fr}
  .kv dt{margin-top:6px}
}
@media (max-width:560px){
  html{font-size:15px}
  .topbar{flex-wrap:wrap}
  .tools{grid-template-columns:1fr}
}
"""


JS_HELPERS = r"""
const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const esc=t=>String(t==null?"":t).replace(/&/g,"&amp;").replace(/</g,"&lt;")
  .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const fmtB=n=>n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB";
let _tt;
function toast(msg,ms=1900){const e=$("#toast");if(!e)return;
  e.textContent=msg;e.classList.add("show");clearTimeout(_tt);
  _tt=setTimeout(()=>e.classList.remove("show"),ms);}
async function apiGet(u){const r=await fetch(u,{headers:{"Accept":"application/json"}});
  if(!r.ok)throw new Error("HTTP "+r.status);return r.json();}
async function apiPost(u,body){const r=await fetch(u,{method:"POST",
  headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):"{}"});
  const j=await r.json().catch(()=>({error:"invalid json"}));
  if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j;}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast("已复制"),
  ()=>{const ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);
    ta.select();document.execCommand("copy");ta.remove();toast("已复制");});}
function debounce(fn,ms=160){let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms);};}

/* 轻量 markdown (标题/列表/代码块/行内代码/粗体/引用/段落) */
function md(src){
  if(!src)return "";
  const blocks=[];let s=esc(src).replace(/\r/g,"");
  s=s.replace(/```([\s\S]*?)```/g,(m,c)=>{blocks.push("<pre><code>"+c.replace(/^\n/,"")+"</code></pre>");
    return "\u0000B"+(blocks.length-1)+"\u0000";});
  const lines=s.split("\n");const out=[];let list=null,inQ=[];let para=[];let table=null;
  const flushPara=()=>{if(para.length){out.push("<p>"+para.join("<br>")+"</p>");para=[];}};
  const flushList=()=>{if(list){out.push("<"+list.t+">"+list.items.join("")+"</"+list.t+">");list=null;}};
  const flushQ=()=>{if(inQ.length){out.push("<blockquote>"+inQ.join("<br>")+"</blockquote>");inQ=[];}};
  const flushTable=()=>{if(table){const rows=table.rows.filter(r=>!/^\|[\s:|-]+\|$/.test(r));
    const cells=r=>r.replace(/^\||\|$/g,"").split("|").map(c=>c.trim());
    const head=cells(rows[0]||""), body=rows.slice(1).map(cells);
    out.push("<div style=\"overflow-x:auto\"><table class=\"tb\"><thead><tr>"
      +head.map(h=>"<th>"+h+"</th>").join("")+"</tr></thead><tbody>"
      +body.map(r=>"<tr>"+r.map(c=>"<td>"+c+"</td>").join("")+"</tr>").join("")
      +"</tbody></table></div>");table=null;}};
  for(const raw of lines){
    const line=raw.trimEnd();
    if(!line.trim()){flushPara();flushList();flushQ();flushTable();continue;}
    if(line.trim().startsWith("|")){flushPara();flushList();flushQ();
      if(!table)table={rows:[]};table.rows.push(line.trim());continue;}
    flushTable();
    let m;
    if((m=line.match(/^###\s+(.*)$/))||(m=line.match(/^##\s+(.*)$/))){
      flushPara();flushList();flushQ();out.push("<h3>"+m[1]+"</h3>");continue;}
    if((m=line.match(/^#\s+(.*)$/))){flushPara();flushList();flushQ();
      out.push("<h3>"+m[1]+"</h3>");continue;}
    if((m=line.match(/^&gt;\s?(.*)$/))){flushPara();flushList();inQ.push(m[1]);continue;}
    if((m=line.match(/^\s*[-*]\s+(.*)$/))){flushPara();flushQ();
      if(!list)list={t:"ul",items:[]};list.items.push("<li>"+m[1]+"</li>");continue;}
    if((m=line.match(/^\s*\d+[.)]\s+(.*)$/))){flushPara();flushQ();
      if(!list)list={t:"ol",items:[]};list.items.push("<li>"+m[1]+"</li>");continue;}
    if(/^\u0000B\d+\u0000$/.test(line)){flushPara();flushList();flushQ();out.push(line);continue;}
    flushList();flushQ();para.push(line);
  }
  flushPara();flushList();flushQ();flushTable();
  let html=out.join("");
  html=html.replace(/`([^`\n]+)`/g,"<code>$1</code>")
           .replace(/\*\*([^*\n]+)\*\*/g,"<strong>$1</strong>");
  html=html.replace(/\u0000B(\d+)\u0000/g,(m,i)=>blocks[+i]);
  return '<div class="md">'+html+"</div>";
}
"""
