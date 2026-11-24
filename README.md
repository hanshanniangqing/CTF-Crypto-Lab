# CTF Crypto Lab v3.2

> 一个开箱即用的**密码学方向 CTF 训练场**：52 道题、44 个工具的密码工具箱、两套本地 Web 界面，全部离线运行。

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

## 特性

- **52 道题，8 个方向**：古典密码 / 对称密码 / 流密码与 PRNG / RSA / 公钥与离散对数 / 哈希 / 格密码 / 口令破解实战。
  每题都带「玩家附件 + 参考题解 + 中文 writeup」，覆盖从 10 分起步题到 500 分的 LWE 格攻击。
- **两个 Web 界面**（纯标准库，无前端构建）：
  - **题目站** `:8787`：概览仪表盘、题目库（搜索/筛选/排序）、**完整题面页**（提交 flag、描述、题目材料内联展开、分步提示、题解、自检）、资源依赖页。
  - **密码工具箱** `:8788`：44 个表单化工具，结果带推导信息，可一键复制。
- **可观察的验证**：点「验证」会展示全过程——实例目录、真实运行命令、脚本 stdout/stderr、flag 提取与逐字比对；可勾选「保留实例」查看现场，也能直接查看参考脚本（带剧透确认）。
- **真实服务实例**：5 道服务型题目可一键启动本地服务，自动分配端口、显示 READY 与连接命令，用完即停。
- **真实破解链路**：cracking 分类接入本机 John the Ripper + rockyou（自动探测，可选），走 `zip2john → john → 还原口令` 的真实流程。
- **提交式判题**：每题都要把算出的 `flag{...}` 填进提交框（或 `python ctf.py submit <题目>`），
  **答对才记为完成**；答错只给格式提示和提交次数，不透露答案。真做不出来可以「放弃并看答案」，
  但会标记为「看过答案」，不计入「独立解出」。
- **全部本地**：只监听 `127.0.0.1`，不联网、不上传任何数据；flag 明文存于仓库，方便自测。

## 零基础学习

从源码启动 `python ctf.py web`，在题目站左侧点击「零基础学习」（`#/learn`）。

1. 先读字符、字节、编码、加密与哈希的区别。
2. 按路线完成 8 道单步练习：Hex → Base64 → ASCII → 二进制 → ROT13 → 已知密钥 XOR → SHA-256 候选匹配 → 取模与 ASCII。每题 10～20 分，无额外资源依赖。
3. 每题的「本题知识点」包含前置基础、原理、操作方向、易错点与相关工具入口；命令行 `python ctf.py info <题目>` 也能查看。
4. 工具页直接显示使用说明与知识点。基础工具可点「填入示例」体验，再替换成题目附件。

新增工具：字节与进制转换、Atbash、培根密码（26 字母版）、字母频率与 IC、手动 XOR、AES ECB/CBC（PKCS#7 / 无填充）。AES 示例使用标准测试向量，解密结果的原始字节见附加 Hex。

验证新增内容：`python tools/test_learning.py`。重新生成起步题：`python tools/build_intro.py`。

## 快速开始

### 方式一：免安装包（Windows，推荐给做题者）

免安装发行包可在 [Releases](https://github.com/hanshanniangqing/CTF-Crypto-Lab/releases) 中查看。源码开源包请使用下面的“方式二”。免安装包解压到任意可写目录后双击：

- `启动题目站.bat` → 浏览器打开题目站
- `启动工具箱.bat` → 浏览器打开密码工具箱
- `CTF-Crypto-Lab.exe` → 同时启动两者

无需安装 Python。关闭黑色控制台窗口即停止服务。

### 方式二：从源码运行（v3.2 开源包）

解压 `CTF-Crypto-Lab-v3.2-开源.zip` 后进入包内目录，先安装 Python 3.10+，再执行 `python -m pip install -r requirements.txt`。安装依赖后可双击 `启动(源码).bat`，或使用下面的命令。

开源包包含完整题目材料、源码、题解与 MIT 许可证；不包含 Python 运行环境、个人进度、外部 John/rockyou 资源。

```bash
git clone https://github.com/hanshanniangqing/CTF-Crypto-Lab.git && cd CTF-Crypto-Lab
pip install -r requirements.txt        # pycryptodome 必需; rich/sympy 强烈推荐

python ctf.py                          # 交互式菜单
python ctf.py web                      # 同时启动题目站 + 工具箱
python ctf.py serve                    # 只启动题目站  http://127.0.0.1:8787
python ctf.py toolkit                  # 只启动工具箱  http://127.0.0.1:8788
```

命令行速查：

```bash
python ctf.py list                    # 题目一览
python ctf.py info  rsa-wiener        # 题目详情
python ctf.py hint  rsa-wiener 1      # 分步提示
python ctf.py gen   rsa-wiener        # 把材料复制到 dist/（网页端材料已直接可见）
python ctf.py submit rsa-wiener       # 提交 flag 判题（答对才记完成）
python ctf.py progress                # 我的进度：分类统计 + 已完成列表
python ctf.py verify rsa-wiener --keep # 自检：跑参考题解看全过程（不计进度）
python ctf.py check all               # 批量自检（52/52）
python ctf.py instance padding-oracle start   # 启动服务实例
python ctf.py doctor                  # 探测 JtR / rockyou / hashcat / 7-Zip
python ctf.py --plain list            # 关闭彩色输出
```

## 题目总览

| # | 题目 | 分类 | 难度 | 分值 | 考点 |
|---|------|------|------|------|------|
| 1 | `intro-hex` | 古典密码 | 入门 | 10 | Hex 字节与文本 |
| 2 | `intro-base64` | 古典密码 | 入门 | 10 | 单层 Base64 解码 |
| 3 | `intro-ascii` | 古典密码 | 入门 | 10 | 十进制 ASCII 转文本 |
| 4 | `intro-binary` | 古典密码 | 入门 | 10 | 二进制字节转文本 |
| 5 | `intro-rot13` | 古典密码 | 入门 | 10 | 固定 ROT13 解密 |
| 6 | `base-nested` | 古典密码 | 入门 | 50 | Base16/32/64/85 嵌套编码识别 |
| 7 | `caesar-rot` | 古典密码 | 入门 | 50 | 凯撒密码爆破 + 英文评分 |
| 8 | `vigenere-classic` | 古典密码 | 简单 | 100 | 重合指数 (IC) 求密钥长度 + 卡方逐列破解 |
| 9 | `affine-brute` | 古典密码 | 简单 | 100 | 仿射密码密钥空间爆破 |
| 10 | `substitution-hillclimb` | 古典密码 | 中等 | 200 | 单表替代密码 + bigram 爬山算法 |
| 11 | `playfair-keysearch` | 古典密码 | 中等 | 200 | Playfair 密码 + 字典密钥爆破 |
| 12 | `hill-knownpt` | 古典密码 | 中等 | 200 | Hill 密码已知明文攻击 (模 26 线性方程组) |
| 13 | `aes-key-from-secret` | 对称密码 | 入门 | 75 | 密钥派生弱点 (key = MD5(用户名)) |
| 14 | `cbc-bitflip` | 对称密码 | 简单 | 150 | CBC 模式 IV 比特翻转 |
| 15 | `des-mitm` | 对称密码 | 中等 | 250 | 双重 DES 中间相遇攻击 (MITM) |
| 16 | `ecb-byte-at-a-time` | 对称密码 | 中等 | 250 | ECB 模式逐字节爆破 (chosen plaintext) |
| 17 | `padding-oracle` | 对称密码 | 困难 | 350 | CBC Padding Oracle 攻击 |
| 18 | `intro-xor` | 流密码与PRNG | 入门 | 20 | 已知单字节密钥 XOR |
| 19 | `rc4-keystream-reuse` | 流密码与PRNG | 简单 | 100 | RC4 密钥流重用 |
| 20 | `lcg-recover` | 流密码与PRNG | 简单 | 150 | LCG 参数恢复 (gcd + 求逆) |
| 21 | `xor-repeating-key` | 流密码与PRNG | 中等 | 200 | 重复密钥 XOR: 汉明距离猜密钥长度 + 频率分析 |
| 22 | `lcg-truncated` | 流密码与PRNG | 中等 | 250 | 截断 LCG 状态恢复 (格 / Babai) |
| 23 | `mt19937-clone` | 流密码与PRNG | 中等 | 250 | MT19937 状态克隆 (untemper) |
| 24 | `intro-mod` | RSA | 入门 | 20 | 取模与 ASCII |
| 25 | `rsa-baby` | RSA | 入门 | 75 | 小模数因式分解 (Pollard rho) |
| 26 | `rsa-small-e` | RSA | 入门 | 100 | 小指数无填充 (直接开 e 次方根) |
| 27 | `rsa-shared-prime` | RSA | 简单 | 100 | 共享素数 (gcd 分解两个模数) |
| 28 | `rsa-common-modulus` | RSA | 简单 | 150 | 共模攻击 (gcd(e1,e2)=1) |
| 29 | `rsa-broadcast` | RSA | 简单 | 150 | Håstad 广播攻击 (e=3, CRT + 立方根) |
| 30 | `rsa-sign-forgery` | RSA | 简单 | 150 | e=3 无填充签名伪造 (立方根) |
| 31 | `rsa-fermat` | RSA | 中等 | 200 | Fermat 分解 (相近素数) |
| 32 | `rsa-wiener` | RSA | 中等 | 250 | Wiener 攻击 (小私钥指数, 连分数) |
| 33 | `rsa-franklin-reiter` | RSA | 中等 | 300 | Franklin-Reiter 相关消息攻击 (多项式 gcd) |
| 34 | `rsa-lsb-oracle` | RSA | 困难 | 350 | RSA 最低位预言机 (二分恢复明文) |
| 35 | `rsa-coppersmith` | RSA | 困难 | 400 | Coppersmith 已知 p 高位分解 |
| 36 | `elgamal-malleable` | 公钥与离散对数 | 简单 | 150 | ElGamal 同态可塑性 |
| 37 | `dsa-nonce-reuse` | 公钥与离散对数 | 中等 | 250 | DSA 随机数 k 重用 |
| 38 | `dh-pohlig-hellman` | 公钥与离散对数 | 中等 | 250 | 光滑阶群上的 Pohlig-Hellman 离散对数 |
| 39 | `ecc-pohlig-hellman` | 公钥与离散对数 | 困难 | 350 | 椭圆曲线光滑阶离散对数 (超奇异曲线) |
| 40 | `dsa-biased-nonce` | 公钥与离散对数 | 困难 | 400 | DSA 随机数高位泄露 (格攻击 HNP) |
| 41 | `intro-hash` | 哈希 | 入门 | 20 | 有限候选 SHA-256 匹配 |
| 42 | `md5-collision` | 哈希 | 入门 | 100 | MD5 碰撞 (前缀碰撞性质) |
| 43 | `password-rules` | 哈希 | 简单 | 100 | 字典攻击 + 规则变形 (hashcat 思路) |
| 44 | `crc32-forgery` | 哈希 | 简单 | 150 | CRC32 线性性伪造 (GF(2) 解方程) |
| 45 | `md5-length-extension` | 哈希 | 中等 | 300 | MD5 长度扩展攻击 (secret-prefix MAC) |
| 46 | `knapsack-merkle-hellman` | 格密码 | 中等 | 300 | Merkle-Hellman 背包 (CJLOSS 格攻击) |
| 47 | `hnp-hidden-number` | 格密码 | 困难 | 400 | 隐数问题 HNP (Boneh-Venkatesan 格) |
| 48 | `lwe-toy` | 格密码 | 专家 | 500 | LWE 小规模原语攻击 (对偶/嵌入格) |
| 49 | `ntlm-crack` | 口令破解实战 | 入门 | 100 | NTLM 哈希字典破解 (John the Ripper + rockyou) |
| 50 | `zip-crack` | 口令破解实战 | 简单 | 150 | ZipCrypto 传统加密压缩包破解 (zip2john + john) |
| 51 | `ssh-key-crack` | 口令破解实战 | 中等 | 250 | 加密 SSH 私钥破解 (ssh2john + john) |
| 52 | `shadow-crack` | 口令破解实战 | 中等 | 300 | sha512crypt 口令破解 (unshadow 场景, $6$) |

推荐顺序：古典 → 哈希/编码 → 对称/流密码 → RSA 基础 → RSA 进阶 → 公钥/离散对数 → 格密码。

## 判题：题目怎么才算「完成」

系统只认一种完成方式——**提交正确的 flag**。

| 你的动作 | 是否记完成 | 说明 |
|----------|-----------|------|
| 在题面页提交框填入正确的 `flag{...}` | ✅ 记完成并加分 | 唯一入口；大小写敏感，全角括号会自动纠正 |
| `python ctf.py submit <题目>` | ✅ 同上 | 与网页读写同一份 `progress.json` |
| 答错 / 格式不对 | ❌ | 只回「不正确」或格式提示，并累计提交次数，不透露答案 |
| 点「自检」跑参考题解 | ❌ | 那是在验证题目材料本身，不是你在解题 |
| 点「放弃并看答案」（或 `ctf.py flag`） | ❌ | 给答案但打「看过答案」标记；之后提交正确仍算完成，只是不计入「独立解出」 |

进度存在项目根目录的 `progress.json`（首次提交时生成，已加入 `.gitignore`），
网页与命令行共用；概览页可以一键重置。

## 自检与实例：它们到底是什么

题面页的「自检」只做一件事：**确认题目材料与参考题解自洽**，与你的做题进度无关。点下去会看到 6 个步骤：

| 步骤 | 实际发生的事 |
|------|--------------|
| ① 创建实例目录 | 把 `challenges/<分类>/<题目>/src/` 的附件复制到 `instances/verify/<题目>/` |
| ② 启动参考题解 | 在同一目录执行 `python …/solution/solve.py`（命令原样显示） |
| ③ 运行完成 | 显示退出码与耗时 |
| ④ 提取 flag | 从 stdout/stderr 正则提取 `flag{...}` |
| ⑤ 与标准答案比对 | 与 `challenges/index.json` 中的 flag 逐字比较 |
| ⑥ 清理 / 保留 | 默认删除临时实例；勾选「保留实例」则保留并给出路径 |

「查看参考脚本」会先弹出剧透确认，再展示 `solve.py` 全文；「打开实例目录」直接在文件管理器里打开现场。

**服务实例**是另一件事：带 `server.py` 的题目（padding-oracle、cbc-bitflip、ecb-byte-at-a-time、rsa-lsb-oracle、md5-length-extension）可以点「启动实例」，
程序会在 `instances/server/<题目>/` 里拉起服务进程，分配一个本机端口，并显示：

```
端口 61155 · READY: READY 61155
实例目录  …/instances/server/padding-oracle
启动命令  …\CTF-Crypto-Lab.exe --run-py …/server.py --port 61155
连接方式  nc 127.0.0.1 61155
```

此时你可用 nc / Python socket / 任意客户端手动攻击；点「停止实例」结束进程。
`elgamal-malleable` 的 `oracle.py` 是 stdin/stdout 工具而不是网络服务，界面会给出本地运行命令。

## 两个 Web 界面

### 题目站（`:8787`）

| 路由 | 内容 |
|------|------|
| `#/` | 已完成/得分/独立解出、分类进度、领取全部题目、自洽性检查（实时队列）、重置进度 |
| `#/learn` | 零基础知识、8 道起步题学习路线、各分类前置基础 |
| `#/challenges` | 搜索（题目名/考点/分类/难度/分值）、难度筛选、三种排序 |
| `#/c/<题目>` | 题面页：**提交 flag** / 描述 / 题目材料内联展开（无需另开窗口）/ 提示逐条揭示 / 题解 / 自检 / 上一题下一题 |
| `#/resources` | JtR、rockyou、hashcat、7-Zip 状态与每题依赖可用性 |

进度由服务端 `progress.json` 提供（不再是浏览器 localStorage），换浏览器、换设备都能接上；
桌面 4 列、平板 2 列、手机 1 列自适应。

### 密码工具箱（`:8788`）

44 个工具，9 个分组：

| 分组 | 工具 |
|------|------|
| 编码 | 自动剥壳、Hex、Base64/32/85、URL、凯撒、摩斯、字节与进制转换 |
| 古典 | 维吉尼亚（IC + 四元组自动破译）、仿射爆破、Playfair、Hill、栅栏、单表替代（频率初始化 + 爬山）、Atbash、培根、字母频率与 IC |
| XOR | 单字节爆破、重复密钥破译、已知明文求密钥流、双密文异或、手动 XOR |
| 对称密码 | AES ECB/CBC 加解密，PKCS#7 / 无填充 |
| 哈希 | 哈希计算、字典破解（rockyou + 规则）、MD5 长度扩展、CRC32 伪造 |
| 数论/RSA | 数论工具、RSA 解密/分解/共模/广播/小指数/共享素数/Wiener/Fermat/Franklin-Reiter/Coppersmith |
| 离散对数 | BSGS、Pohlig-Hellman、椭圆曲线点运算与 ECDLP |
| PRNG | MT19937 克隆、LCG 参数恢复、截断 LCG 格恢复 |
| 格 | HNP 隐数问题、背包 CJLOSS |

每个工具页提供入门知识、原理、参数说明、操作步骤和常见错误；部分工具提供可直接运行的独立示例。结果可复制并保留会话内历史；`Ctrl/⌘+Enter` 运行。

## 目录结构

```
CTF-Crypto-Lab/
├── ctf.py                  # 入口：CLI / Web / 打包后充当 Python 解释器 (--run-py)
├── labenv.py               # 路径定位（源码/打包、只读资源/可写目录）
├── instances.py            # 验证实例与服务实例管理
├── progress.py             # flag 判题 + 做题进度（progress.json，CLI/Web 共用）
├── webconsole.py           # 题目站（多页面 SPA + JSON API）
├── toolkit_web.py          # 密码工具箱（44 个工具）
├── lib/
│   ├── ctfk.py             # 密码学工具箱（LLL/Coppersmith/HNP/DLog/MT19937/MD5 等）
│   ├── ui.py               # 终端 UI（rich，自动降级）
│   ├── webbase.py          # 两个 Web 界面共用的设计系统（CSS + JS 基础库）
│   └── data/               # 英文语料、词表、已验证的 MD5 碰撞样本
├── challenges/
│   ├── index.json          # 题目注册表（flag/难度/提示/超时/资源依赖）
│   └── <分类>/<题目>/
│       ├── src/            # 玩家附件（服务题含 server.py / oracle.py）
│       └── solution/       # solve.py + writeup.md
├── tools/
│   ├── build_*.py          # 出题脚本（确定性种子，可完整复现材料）
│   ├── build_common.py     # 出题公共设施
│   ├── resources.py        # 外部工具探测（JtR/rockyou/hashcat/7-Zip）
│   ├── test_ctfk.py        # 工具箱单元测试
│   ├── make_writeups.py    # 从 solve.py docstring 生成 writeup.md
│   └── build_readme.py     # 重新生成 README 题目表
├── scripts/build_release.py # 一键打包 Windows 免安装版 + zip
├── docs/使用说明.txt        # 提供给最终用户的说明（会打包进发行版）
├── ctf_crypto_lab.spec     # PyInstaller 配置
└── CONVENTIONS.md          # 出题 / 解题 / Web 二开规范
```

运行时生成（已在 .gitignore 中）：`dist/`（领取的题目）、`instances/`（验证与服务实例）、`lib/resources.json`（资源探测缓存）、`progress.json`（做题进度）。

## 工具箱 `lib/ctfk.py`

纯 Python 实现的密码学原语，35 项单元测试（`python tools/test_ctfk.py`）：

| 模块 | 代表 API |
|------|----------|
| 数论 | `iroot` `modinv` `crt` `factorint` `is_prime` `randprime` |
| RSA | `wiener` `fermat_factor` `small_roots`(Coppersmith) `poly_gcd_modn`(Franklin-Reiter) |
| 离散对数 | `bsgs` `pohlig_hellman` `EC` + `ec_bsgs` / `ec_pohlig` |
| 格 | `lll`（精确，sympy 优先）`babai` `solve_hnp` |
| PRNG | `MT19937` `clone_mt` `untemper` `LCG` `solve_lcg_params` `solve_lcg_truncated` |
| 对称/古典 | `rc4` `pkcs7_*` `Playfair` `vigenere` `hill_key_from_knownpt` `BigramModel` |
| 哈希 | 纯 Python `md5`（可长度扩展）`md5_lenext` `crc32_patch` |
| 其他 | `pem_decrypt`（传统 PEM 私钥）`try_decode_layers`（自动剥壳） |

## 出题 / 二次开发

- 每题 = 一个 gen 函数（`tools/build_*.py`）+ 一个 solve 脚本 + `index.json` 登记项。
- gen 使用**确定性随机种子**，`python ctf.py regen all` 可完整复现全部材料；gen 内部用攻击逻辑反推答案做自检。
- 新增题目：登记 → 写 gen/solve → `python tools/make_writeups.py` → `python tools/build_readme.py` → `python ctf.py check <题目>`。
- 详细规范（含服务题协议、Web API、工具箱扩展）见 **CONVENTIONS.md**。

## 打包发行

生成干净的开源源码包（会包含尚未提交的源码改动）：

```bash
python scripts/build_source_release.py
# → release/CTF-Crypto-Lab-v3.2-开源.zip
# → release/CTF-Crypto-Lab-v3.2-开源.zip.sha256
```

包内排除 Git 历史、Python 缓存、外部资源路径缓存、个人进度、运行实例与构建产物。题目自带的 SSH 私钥、碰撞样本和加密压缩包属于练习附件，会保留。

生成 Windows 免安装包：

```bash
pip install -r requirements.txt -r requirements-dev.txt
python scripts/build_release.py
# → build_dist/CTF-Crypto-Lab/           可直接双击的目录
# → release/CTF-Crypto-Lab-v3.2-win64.zip
```

打包版内置 Python 与依赖，目标机器无需安装任何环境；程序会以自身充当解释器运行题目脚本（`--run-py`）。

## 说明与声明

- 所有加密材料与 flag 均为**本地教学用途**；flag 明文存放于 `index.json` 与部分服务脚本中，这是刻意设计（本地练习场的判题机就是你自己）。
- 服务型题目只监听 `127.0.0.1`；请勿将本项目的服务暴露到公网。
- cracking 分类依赖本机的 John the Ripper 与 rockyou 词表，均不随仓库分发；缺失时程序会给出明确提示。
- 语料来自古腾堡计划公开文本，词表来自 google-10000-english，MD5 碰撞样本为学术界公开的 Wang 攻击示例。

## 许可

[MIT](LICENSE) © 2026 CTF Crypto Lab contributors

欢迎提交 Issue / PR：新题目、新工具、题解改进都很有价值。新增内容请遵循 `CONVENTIONS.md`，并保证 `python ctf.py check all` 全绿。
