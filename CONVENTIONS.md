# CTF Crypto Lab 出题规范 (CONVENTIONS)

本文件是本项目中**出题与解题脚本的强制规范**。所有参与者（含自动化助手）必须遵守。

## 1. 目录结构

```
ctf-crypto-lab/
  ctf.py                     # 平台 CLI (已存在, 勿改)
  challenges/
    index.json               # 题目注册表 (已存在, 勿改; flag/难度/提示都在里面)
    <category>/<name>/
      src/                   # 玩家附件 (由 build 脚本生成)
      solution/
        solve.py             # 解题脚本 (check 会运行它并核对 flag)
        writeup.md           # 题解 (由 make_writeups.py 从 solve.py docstring 生成, 不手写)
  lib/
    ctfk.py                  # 密码学工具箱 (已存在, 勿改; 若发现 bug 只能报告, 由负责人统一修复)
    data/                    # 语料/词表/MD5碰撞样本
  tools/
    build_common.py          # 出题公共设施 (已存在, 勿改)
    build_*.py               # 各分类出题脚本 (每人/每任务负责一个文件, 互不冲突)
    test_ctfk.py             # 工具库测试 (已存在)
```

## 2. 出题脚本 (tools/build_X.py)

* 从 `build_common import *`；用 `@register("题目名")` 注册生成函数 `fn(ch)`，
  `ch` 是 index.json 里该题的元数据 dict（`ch["flag"]` 是本题答案）。
* **确定性**：所有随机性必须来自 `rng = rng_for("题目名")`（跨平台一致的种子）。
  禁止使用全局 random、time、os.urandom 参与材料生成。
* 附件写入 `write_src(题目名, 文件名, 文本或bytes)`。文件名固定、内容格式自解释
  （十六进制大写或小写均可，但须在附件里注明格式或用 .json/.txt 区分）。
* 每题至少 2 条 `verify(题目名, 条件, 说明)` 自检，关键的一条是：
  **用生成参数反推一遍答案**（如用私钥解密密文 == flag），确保材料自洽。
* `if __name__ == "__main__": run_builders(BUILDERS)` 结尾。单题调试可用环境变量：
  `CTF_REGEN_ONLY="rsa-baby" python tools/build_c_rsa.py`
* **切勿在 build 脚本里写 `BUILDERS = {}`** —— `build_common` 已提供注册表，
  重新赋值会覆盖 import 来的引用导致所有题目静默不生成。
* 生成的 src/ 会提交进版本库；改动 gen 逻辑后重跑以刷新 src/。

## 3. 解题脚本 (solution/solve.py)

固定头部（ROOT 计算依赖 4 层目录深度，勿改）：

```python
"""题解：题目名
## 漏洞点
(为什么会被攻破, 3~6 行中文)
## 利用思路
(攻击步骤, 编号列表)
## 关键代码
(核心代码片段, 10 行以内)
## 防御建议
(2~4 条)
"""
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "lib"))
import ctfk
# 需要的第三方库: pycryptodome (Crypto), sympy 可用但优先用 ctfk

# 读附件: 一律基于当前工作目录 (check 会在实例目录运行)
data = open("output.txt").read()
...
print(flag)   # 最后必须 print 出 flag{...}, check 靠 stdout 中的 flag{...} 判定
```

* solve.py **不知道** flag 是什么，必须真正从材料里恢复。
* 不得修改题目附件、不得读取 index.json、不得硬编码答案。
* 运行时间须低于 index.json 里的 timeout。
* docstring 是 writeup 的唯一来源，务必按上面的 `##` 结构写，中文。

## 4. 带服务器的题目 (server 类)

部分题目的 src/ 里有一个 `server.py`（由 gen 脚本生成），约定：

* `python server.py --port N` 启动，绑定 127.0.0.1:N；`--port 0` 表示系统分配。
* 行协议：客户端发一行请求（hex/命令），服务端回一行响应，循环直到 EOF。
* 服务端启动后**必须立刻** `sys.stdout.write("READY\n"); sys.stdout.flush()`。
* flag 以明文写在 server.py 内（gen 时由 ch["flag"] 填入）。
* solve.py 用 `subprocess.Popen([sys.executable, "server.py", "--port", "0"], cwd=os.getcwd(), stdout=PIPE)` 启动服务端，读一行 "READY"（若用 port 0，server 把实际端口写在 READY 行，如 `READY 54321`），攻击完 `proc.kill()`，用 try/finally 保证清理。
* solve.py 里 `time.sleep(0.05)` 等启动；连接用 `socket.create_connection(("127.0.0.1", port), timeout=5)`。

## 5. 依赖与工具箱

* 允许：标准库、`pycryptodome`（`from Crypto.Cipher import AES/DES/PKCS1_OAIP...`）、`ctfk`。
  `sympy` 已安装可用于解题，但**优先用 ctfk** 的实现（性能可控）。
* ctfk 常用 API（完整列表见 lib/ctfk.py 模块注释）：

```
b2l(bytes)->int, l2b(int)->bytes, xor_bytes, iroot(n,k), modinv, crt(pairs)
is_prime, randprime(bits, rng), factorint(n)          # 因式分解 (n<=~2^80 快)
convergents(a,b), wiener(e,n), fermat_factor(n)
bsgs(g,h,p,order), pohlig_hellman(g,h,p,factors)      # 乘法群 DLP
EC(a,b,p): .add .mul .sub .neg .on .ec_bsgs(P,Q,order) .ec_pohlig(P,Q,factors)
lll(matrix)                                            # sympy 支持的精确 LLL
small_roots(coeffs, n, beta, X, m, t)                  # Coppersmith; f 必须首一
solve_hnp(samples,p,B)                                 # a_i*x - e_i = c_i (mod p), |e_i|<B
solve_lcg_params(outputs), solve_lcg_truncated(m,a,c,highs,shift)
MT19937(seed), clone_mt(outputs), untemper, LCG(a,c,m,seed)
rc4, pkcs7_pad/unpad/valid, hamming_bits
caesar_shift, vigenere, affine_decrypt, Playfair(key).encrypt/decrypt
mat_mul_mod, hill_key_from_knownpt(pt_blocks, ct_blocks, n=26)
chi2_english(text), BigramModel().score(text)          # 英文评分
md5(纯py), md5_pad, md5_compress, md5_lenext(digest, prefix_len, suffix)
crc32_patch(prefix, target), gf2_solve
try_decode_layers(data)                                # 自动剥编码
```

* 大素数生成用 `ctfk.randprime(bits, rng)`（把 rng 传入保证确定性）。

## 6. 工作流 (每个题目)

1. 写 gen 函数 → `CTF_REGEN_ONLY="<name>" python tools/build_X.py` 生成 src/ 并看自检。
2. 手动检查 src/ 文件内容合理（player 视角能看懂、格式干净）。
3. 写 solution/solve.py。
4. `python ctf.py check <name>` 直到 PASS（自动生成临时实例→运行 solve→比对 flag）。
5. 全部完成后运行 `python ctf.py check <你的所有题目>` 整体确认。

## 7. 质量要求

* writeup 中文、准确、面向「学过一点密码学的学生」，讲清原理而不是堆代码。
* 题目材料在真实感与解题速度之间平衡；参数留足余量（统计/格攻击 100% 可解）。
* 不引入新的第三方依赖；不改共享文件（ctfk.py / ctf.py / index.json / build_common.py），
  发现 bug 在最终报告里说明，由负责人统一修。

## 8. 外部资源与 cracking 分类

**资源探测**（`tools/resources.py`）扫描磁盘浅层目录，结果缓存到 `lib/resources.json`：

```python
import resources as RES
res = RES.get_resources()            # 缓存的探测结果
res["john"]      # {"exe": ..., "home": ..., "version": ...} 或 None
res["rockyou"]   # {"path": ..., "gz": bool, "lines": int} 或 None
res["hashcat"]   # {"exe": ...} 或 None
res["sevenzip"]  # {"exe": ...} 或 None
for pw in RES.rockyou_iter(res, limit=100000): ...   # 迭代口令 bytes
RES.rockyou_line(res, 73907)                         # 取第 N 行 (1-based)
```

环境变量 `CTF_RES_ROOTS="D:\;E:\"` 可覆盖扫描根目录；`python ctf.py doctor --rescan` 刷新缓存。

**cracking 分类的硬性要求**：

1. `index.json` 里必须声明 `"requires": ["john", "rockyou", ...]`，`ctf.py doctor` 会按此
   输出每题的资源可用性；缺资源时题目应给出明确依赖提示。
2. gen 生成材料时，口令优先从 rockyou 确定性抽取（`RES.rockyou_line` + `rng_for`），
   无 rockyou 时降级到脚本内置迷你词表——**保证任何环境都能 build**。
3. solve.py 必须**真正使用 John the Ripper**（zip2john / ssh2john / 直接喂 hash），
   允许有纯 Python 降级路径（如 NTLM 用 MD4 枚举），但主路径应为 john 工作流，
   以对齐真实竞赛/渗透经验。
4. 解析 john 破解结果**统一读 `--pot` 文件**（`<hash>:<password>`），不要解析 `--show`
   的表格输出（字段含文件名/冒号，易错）。
5. flag 必须**依赖破解结果**（如 flag = Administrator 的口令，或 = 破解口令派生密钥
   解开的密文），不能是无关常量。
6. 已知环境坑（Windows）：
   * `ssh2john.py` (JtR 1.9 jumbo) 使用已移除的 `base64.decodestring`，需 shim
     `base64.decodestring = base64.decodebytes` 后再执行。
   * `openssl` 为 mingw64 版时，路径一律用 `Path.as_posix()`。
   * 生成加密 zip 用 `7z a -tzip -mem=ZipCrypto -p<pw>`；ssh 私钥用
     `ssh-keygen -m PEM`（新 OpenSSH 输出 AES-128-CBC，不是 DES-EDE3-CBC）。

## 9. Web 界面约定 (两个独立应用)

项目有两个 Web 服务，共用 `lib/webbase.py` 的设计系统（BASE_CSS + JS_HELPERS）：

| 服务 | 文件 | 默认端口 | 启动 |
|------|------|----------|------|
| 题目站 | `webconsole.py` | 8787 | `python ctf.py serve` |
| 密码工具箱 | `toolkit_web.py` | 8788 | `python ctf.py toolkit` |
| 两者同时 | 二者 | 8787/8788 | `python ctf.py web` |

**题目站**：hash 路由 `#/`（概览）、`#/challenges`、`#/c/<name>`、`#/resources`；API:
GET `index / hints / writeup / files / file / download / script / progress / resources / instances`，
POST `submit/<name> / giveup/<name> / progress/reset / check/<name> / gen/<name> / gen-all / verify/<name> / instance/...`。

**判题约定（重要）**：
* 「完成」只有一个入口 —— `progress.submit()`。GET 侧不提供明文 flag 接口
  （旧 `/api/flag/<name>` 已移除），任何新功能都不得绕过判题直接把题标记为完成。
* 参考题解自检（`check` / `verify` / `#/c/<name>` 的「自检」）**只验证题目材料自洽**，
  与做题进度无关，禁止在其中写入进度。
* 看过答案走 `progress.peek()`：只打 `peeked` 标记，不置 `solved`；
  `peeked` 的题完成时仍计入总分，但不计入「独立解出」(`clean`)。
* 判题输入先经 `progress.normalize()`（去空白、全角括号归一），再用
  `hmac.compare_digest` 比对，严格区分大小写。
* 进度文件固定为 `WLAB/progress.json`，读写必须走 `progress.py`，不要各自开文件。

**工具箱**：路由 `#/`、`#/t/<id>`、`#/docs`；API: GET `tools`，POST `tool/<id>`。

**新增工具箱工具**：在 `toolkit_web.py` 写处理函数 `fn(fields) -> {ok, result, extras, steps}`，
再往 `TOOLS` 列表追加
`{"id","group","name","desc","fields":[F(...)|SEL(...)],"fn"}`；示例输入可选加 `EXAMPLES`。
约束：只能调用 ctfk/标准库；异常由 HTTP 层统一转成友好错误；重计算工具需在 desc 注明。

**通用硬性要求**：
* 新增 API 必须做路径白名单校验（禁止 `..` 与分隔符）、返回 JSON、异常时回 4xx/5xx。
* 前端所有动态文本必须经 `esc()` 转义后插入 DOM（提示/描述/文件名可能含 `<`）。
* **元素 id 全局唯一**——曾因按钮与内容盒共用 `id="mwu"` 导致 markdown 注入按钮内。
* 共享 JS 在 `lib/webbase.py`：`$` `$$` `esc` `md`（含表格）`toast` `apiGet` `apiPost`
  `copyText` `debounce` `fmtB`。修改后两个服务同时生效。
* 响应式：≥1100px 多列、~820px 2 列、<640px 1 列；侧边栏在 <960px 变为顶部图标条。
* CLI 侧（`lib/ui.py`）：所有输出走 `UI` 类，rich 可用时表格/面板/进度条，
  否则 ANSI 纯文本（`--plain` 强制）；`_strip()` 剥掉降级模式残留的 rich 标记。

## 10. 运行环境、实例与打包

* **路径**：一切路径派生自 `labenv.LAB`（只读资源根）与 `labenv.WLAB`（可写根，
  不可写时回退到 `%LOCALAPPDATA%/CTF-Crypto-Lab`）。禁止在代码里写死绝对路径，
  也禁止把运行时产物（dist/、instances/、resources.json）写进源码目录。
* **实例**：验证实例由 `instances.run_reference_solution()` 统一管理，
  必须返回可展示的 `steps`（标题 + 详情 + 状态），并在结束时清理或保留（keep）。
  新增「运行脚本」的能力一律复用该函数，不要各自写 subprocess。
* **服务实例**：仅 `src/server.py` 视为网络服务（行协议 + READY 输出）；
  `oracle.py` 是 stdin/stdout 工具，不要试图给它分配端口。
  启动/停止必须经 `instances.start_server()/stop_server()`，以便统一回收子进程。
* **打包运行**：程序在 PyInstaller 环境下以自身充当解释器（`<exe> --run-py <script>`），
  因此 solve/server/oracle 里可以直接用 `sys.executable` 启动同目录的 .py 脚本 ——
  但**不要**再用 `sys.executable -c "..."`（exe 不支持 -c）。
* **回归门槛**：任何改动后至少跑 `python tools/test_ctfk.py` 与 `python ctf.py check all`；
  改动判题/进度相关代码时，还要覆盖三种输入：错误 flag（不记完成）、正确 flag（记完成并加分）、
  重复提交（不重复计分），以及 `giveup` 后提交正确 flag（计入 `peeked`、不计入 `clean`）。
  涉及打包的改动还要在 `build_dist/` 里复跑一遍 `CTF-Crypto-Lab.exe check all`。
