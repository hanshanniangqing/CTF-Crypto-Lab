from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes.fromhex(data).decode())
