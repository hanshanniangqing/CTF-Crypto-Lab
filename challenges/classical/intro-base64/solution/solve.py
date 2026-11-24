from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import base64
print(base64.b64decode(data).decode())
