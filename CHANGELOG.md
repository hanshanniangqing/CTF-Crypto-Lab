# 更新日志

## v3.0 — 可观察验证 + 服务实例 + 免安装发行版

**验证过程完全可见**
- 新增 `instances.py`：验证实例统一复制到 `instances/verify/<题目>/`，并记录每一步
  （创建目录 → 运行命令 → 退出码 → 提取 flag → 比对 → 清理/保留）。
- 题面页「验证」标签重写：时间线展示 6 个步骤、真实启动命令、stdout/stderr、
  实例路径；新增「保留实例」「打开实例目录」「查看参考脚本（剧透确认）」。
- CLI 新增 `ctf.py verify <题目> [--keep]`，终端同样展示完整过程。

**服务实例**
- 带 `server.py` 的题目可一键启动：自动挑选空闲端口、读取 READY、显示连接命令，
  支持停止与再次启动；`ctf.py instance <题目> start|stop|list`。
- `oracle.py` 类题目识别为 stdin/stdout 工具，界面给出本地运行命令。

**打包与跨机运行**
- 新增 `labenv.py`：源码/打包统一的路径定位；不可写目录自动回退到
  `%LOCALAPPDATA%\CTF-Crypto-Lab`。
- 打包后程序以自身充当 Python 解释器（`--run-py`），题目里的
  `server.py / oracle.py / verify.py` 均可在无 Python 环境的机器上运行。
- 新增 `ctf_crypto_lab.spec` 与 `scripts/build_release.py`，产出免安装目录与 zip。

**Web 界面完善**
- 端口被占用时自动顺延，并在服务就绪后才打开浏览器。
- 资源探测缓存改写到可写目录，避免只读安装位置失败。
- 修复重启实例时 Windows 文件占用导致的启动失败（自动换用新目录）。

## v2.0 — 双 Web 界面 + 密码工具箱 + 真实破解

- 题目站重写为多页面应用（概览 / 题目库 / 完整题面页 / 资源页），
  支持搜索、筛选、排序、附件预览下载、提示逐条揭示、题解渲染、进度持久化。
- 新增密码工具箱（`toolkit_web.py`，38 个工具，8 个分组），独立端口与界面。
- 新增 `cracking` 分类 4 题：NTLM / ZipCrypto / SSH 私钥 / shadow，
  接入本机 John the Ripper + rockyou（`tools/resources.py` 自动探测）。
- 共享设计系统 `lib/webbase.py`；`lib/ui.py` 提供 rich 终端 UI 与降级模式。
- 题库从 40 题扩充到 44 题，全部自动化验证通过。

## v1.0 — 40 题题库与工具箱

- 44 → 40 题基线：古典 7、对称 5、流密码 5、RSA 11、公钥 5、哈希 4、格 3。
- `lib/ctfk.py` 密码学工具箱：LLL、Coppersmith、HNP、Pohlig-Hellman（群/EC）、
  MT19937 克隆、可长度扩展的纯 Python MD5、CRC32 补丁等，35 项单元测试。
- `ctf.py` CLI：list / info / hint / gen / check / flag / writeup / regen。
- 出题脚本确定性可复现，gen 内置攻击逻辑自检。
