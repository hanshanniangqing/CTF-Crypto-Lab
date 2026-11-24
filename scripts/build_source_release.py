"""生成干净的开源源码 ZIP（包含尚未提交的源码改动，不包含本机运行状态）。"""
import hashlib
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIRS = {'.github', 'challenges', 'docs', 'lib', 'scripts', 'tools'}
SKIP = {'__pycache__', '.git', '.venv', 'venv', 'env', 'node_modules',
        '.pytest_cache', 'dist', 'instances', 'build', 'build_dist', 'release'}
ROOT_FILES = {'.gitattributes', '.gitignore', 'LICENSE'}
ROOT_SUFFIXES = {'.py', '.md', '.txt', '.bat', '.spec'}
TEXT_SUFFIXES = {'.py', '.md', '.txt', '.json', '.yml', '.yaml', '.spec', '.bat'}
PRIVATE_MARKERS = ['C:' + chr(92) + 'Users', 'D:' + chr(92) + 'rockyou',
                   'D:' + chr(92) + 'John', '40' + '928']

def source_files():
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(ROOT)
        if any(part in SKIP for part in rel.parts):
            continue
        if len(rel.parts) == 1:
            if p.name not in ROOT_FILES and p.suffix not in ROOT_SUFFIXES:
                continue
        elif rel.parts[0] not in DIRS:
            continue
        if p.suffix in {'.pyc', '.pyo', '.log', '.tmp', '.bak'} or p.name in {'resources.json', 'progress.json', 'progress.json.tmp'}:
            continue
        if p.suffix in TEXT_SUFFIXES:
            text = p.read_text(encoding='utf-8', errors='replace')
            if any(marker in text for marker in PRIVATE_MARKERS):
                raise SystemExit('发现本机信息，请先检查: ' + rel.as_posix())
        yield p

def main():
    match = re.search(r'^VERSION = "CTF Crypto Lab v([^"\s]+)"',
                      (ROOT/'ctf.py').read_text(encoding='utf-8'), re.MULTILINE)
    if not match:
        raise SystemExit('无法读取版本号')
    name = 'CTF-Crypto-Lab-v' + match.group(1) + '-开源'
    out_dir = ROOT/'release'
    out_dir.mkdir(exist_ok=True)
    out = out_dir/(name+'.zip')
    files = list(source_files())
    if not files:
        raise SystemExit('未找到源码')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for p in files:
            archive.write(p, (Path(name)/p.relative_to(ROOT)).as_posix())
    with zipfile.ZipFile(out) as archive:
        bad = archive.testzip()
        if bad:
            raise SystemExit('压缩包校验失败: ' + bad)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_suffix('.zip.sha256').write_text(digest+'  '+out.name+'\n', encoding='utf-8')
    print(f'{out.name}: {len(files)} files, {out.stat().st_size:,} bytes')
    print('SHA256: ' + digest)

if __name__ == '__main__':
    main()
