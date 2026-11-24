from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import codecs
print(codecs.decode(data, 'rot_13'))
