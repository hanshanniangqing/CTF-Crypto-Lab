# 取模与 ASCII

## 思路
附件第一行是模数，其余数字按顺序取模，再把余数作为十进制 ASCII 转文本。

## 操作
例如 321 mod 256 = 65，对应 A；先取余再转换字节。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
nums = [int(x) for x in data.split()]
print(bytes(x % nums[0] for x in nums[1:]).decode())
```

## 结果与复盘
flag{mod_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
