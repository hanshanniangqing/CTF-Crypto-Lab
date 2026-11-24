from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes(int(x, 2) for x in data.split()).decode())
