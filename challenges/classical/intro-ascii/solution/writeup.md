# 十进制 ASCII 转文本

## 思路
附件每个十进制数字对应一个字符，请按顺序还原。

## 操作
字节转换工具选择十进制字节解码。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes(int(x) for x in data.split()).decode())
```

## 结果与复盘
flag{ascii_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
