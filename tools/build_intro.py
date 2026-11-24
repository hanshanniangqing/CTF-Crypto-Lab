"""生成零基础单步练习的附件与参考脚本，无外部依赖。"""
import base64
import codecs
import hashlib
import json
import os
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
SPECS = [
    ('intro-hex', 'classical', 'Hex 字节与文本', '把附件中的十六进制解码一次，找到 flag。', 'flag{hex_first_step}', "print(bytes.fromhex(data).decode())", 'Hex 每两位是一字节，选择 Hex 工具的解码方向。'),
    ('intro-base64', 'classical', '单层 Base64 解码', '附件只经过一次 Base64 编码，请还原文本。', 'flag{base64_first_step}', "import base64\nprint(base64.b64decode(data).decode())", 'Base 工具选择 Base64 与解码。'),
    ('intro-ascii', 'classical', '十进制 ASCII 转文本', '附件每个十进制数字对应一个字符，请按顺序还原。', 'flag{ascii_first_step}', "print(bytes(int(x) for x in data.split()).decode())", '字节转换工具选择十进制字节解码。'),
    ('intro-binary', 'classical', '二进制字节转文本', '附件每组 8 位二进制对应一个字符，请还原文本。', 'flag{binary_first_step}', "print(bytes(int(x, 2) for x in data.split()).decode())", '字节转换工具选择二进制字节解码。'),
    ('intro-rot13', 'classical', '固定 ROT13 解密', '附件英文字母都移动了 13 位。数字、括号、下划线保持不变。', 'flag{rot13_first_step}', "import codecs\nprint(codecs.decode(data, 'rot_13'))", '凯撒工具选择解密，位移填 13。'),
    ('intro-xor', 'stream', '已知单字节密钥 XOR', '密文以 Hex 保存；密钥是十六进制 2a。将每个密文字节与 0x2a 异或。', 'flag{xor_first_step}', "print(bytes(x ^ 0x2a for x in bytes.fromhex(data)).decode())", '手动 XOR 工具中密文与密钥均选 Hex；密钥填 2a。'),
    ('intro-hash', 'hash', '有限候选 SHA-256 匹配', '附件第一行是 SHA-256 摘要，其余行是候选口令。找到命中的口令，提交 flag{口令}。', 'flag{sunshine}', "import hashlib\nlines = data.splitlines()\nfor word in lines[1:]:\n    if hashlib.sha256(word.encode()).hexdigest() == lines[0]:\n        print('flag{' + word + '}')", '依次计算候选词的 SHA-256；不要把行末换行加入口令。'),
    ('intro-mod', 'rsa', '取模与 ASCII', '附件第一行是模数，其余数字按顺序取模，再把余数作为十进制 ASCII 转文本。', 'flag{mod_first_step}', "nums = [int(x) for x in data.split()]\nprint(bytes(x % nums[0] for x in nums[1:]).decode())", '例如 321 mod 256 = 65，对应 A；先取余再转换字节。'),
]

def build():
    index = json.loads((LAB / 'challenges/index.json').read_text(encoding='utf-8'))
    by_name = {c['name']: c for c in index['challenges']}
    for i, (name, cat, topic, desc, flag, code, hint) in enumerate(SPECS):
        only = os.environ.get('CTF_REGEN_ONLY', '')
        if only and name not in only.split(','):
            continue
        # 元数据由 index.json 管理；重新出题会同时验证附件与索引答案一致。
        c = by_name[name]
        assert c['flag'] == flag
        raw = flag.encode()
        data = {
            'intro-hex': lambda: raw.hex(),
            'intro-base64': lambda: base64.b64encode(raw).decode(),
            'intro-ascii': lambda: ' '.join(str(x) for x in raw),
            'intro-binary': lambda: ' '.join(format(x, '08b') for x in raw),
            'intro-rot13': lambda: codecs.encode(flag, 'rot_13'),
            'intro-xor': lambda: bytes(x ^ 0x2a for x in raw).hex(),
            'intro-hash': lambda: hashlib.sha256(b'sunshine').hexdigest() + '\napple\nwelcome\nsunshine\ncrypto',
            'intro-mod': lambda: '256\n' + ' '.join(str(x + 256 * (j + 1)) for j, x in enumerate(raw)),
        }[name]()
        root = LAB / 'challenges' / cat / name
        (root / 'src').mkdir(parents=True, exist_ok=True)
        (root / 'solution').mkdir(exist_ok=True)
        (root / 'src/data.txt').write_text(data + '\n', encoding='utf-8')
        script = "from pathlib import Path\ndata = Path('data.txt').read_text(encoding='utf-8').strip()\n" + code + '\n'
        (root / 'solution/solve.py').write_text(script, encoding='utf-8')
        (root / 'solution/writeup.md').write_text(
            '# ' + topic + '\n\n## 思路\n' + desc + '\n\n## 操作\n' + hint +
            '\n\n## 参考脚本\n在附件目录执行以下脚本：\n\n```python\n' + script +
            '```\n\n## 结果与复盘\n' + flag + '\n解释输入的表示形式，再用相反方向的运算检查能否得到原附件。\n', encoding='utf-8')
        print('[build] ' + name + ': OK')

if __name__ == '__main__':
    build()
