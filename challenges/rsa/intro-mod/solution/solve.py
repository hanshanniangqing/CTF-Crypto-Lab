from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
nums = [int(x) for x in data.split()]
print(bytes(x % nums[0] for x in nums[1:]).decode())
