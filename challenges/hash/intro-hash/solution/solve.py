from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import hashlib
lines = data.splitlines()
for word in lines[1:]:
    if hashlib.sha256(word.encode()).hexdigest() == lines[0]:
        print('flag{' + word + '}')
