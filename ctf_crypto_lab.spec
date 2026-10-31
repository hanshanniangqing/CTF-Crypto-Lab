# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置 —— 生成免安装 Windows 发行版

    python -m PyInstaller ctf_crypto_lab.spec --noconfirm

产物: build_dist/CTF-Crypto-Lab/
  ├── CTF-Crypto-Lab.exe      双击即启动 Web 界面
  ├── challenges/             题目 (附件 + 题解 + 索引)
  ├── lib/                    工具箱与数据 (ctfk/ui/webbase/语料/词表/碰撞样本)
  ├── tools/resources.py      外部工具探测
  ├── README.md               使用说明
  └── _internal/              运行时依赖 (Python/加密库/sympy)
"""
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

LAB = Path(SPECPATH).resolve()

datas = []


def add_dir(src: Path, dst: str, patterns=("**/*",), exclude_dirs=()):
    if not src.exists():
        return
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(src)
        if any(part in exclude_dirs for part in rel.parts):
            continue
        if "__pycache__" in rel.parts or p.suffix == ".pyc":
            continue
        datas.append((str(p), str(Path(dst) / rel.parent)))


# 题目: index.json + 各题 src/ 与 solution/ (solve.py 需要真实文件供 --run-py 执行)
add_dir(LAB / "challenges", "challenges", exclude_dirs=())
# 工具箱与数据
datas.append((str(LAB / "lib" / "ctfk.py"), "lib"))
datas.append((str(LAB / "lib" / "ui.py"), "lib"))
datas.append((str(LAB / "lib" / "webbase.py"), "lib"))
add_dir(LAB / "lib" / "data", "lib/data")
# 外部资源探测
datas.append((str(LAB / "tools" / "resources.py"), "tools"))
# 文档
for doc in ("README.md", "CONVENTIONS.md", "requirements.txt"):
    p = LAB / doc
    if p.exists():
        datas.append((str(p), "."))

hiddenimports = [
    "progress",  # 顶层模块, 判题与进度; 显式声明避免懒加载漏收
    "Crypto", "Crypto.Cipher", "Crypto.Cipher.AES", "Crypto.Cipher.DES",
    "Crypto.Cipher.DES3", "Crypto.Cipher.PKCS1_OAEP", "Crypto.Hash", "Crypto.Hash.MD4",
    "Crypto.PublicKey", "Crypto.PublicKey.RSA", "Crypto.Util", "Crypto.Util.number",
    "sympy", "mpmath",
]

a = Analysis(
    [str(LAB / "ctf.py")],
    pathex=[str(LAB), str(LAB / "lib")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy", "pandas", "IPython",
              "pytest", "setuptools", "pip", "PIL", "PyInstaller"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CTF-Crypto-Lab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,              # 保留控制台: 便于查看端口/日志; Ctrl+C 结束
    disable_windowed_traceback=False,
    contents_directory=".",
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CTF-Crypto-Lab",
)
