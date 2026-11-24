from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes(x ^ 0x2a for x in bytes.fromhex(data)).decode())
