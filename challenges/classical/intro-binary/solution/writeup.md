# 二进制字节转文本

## 思路
附件每组 8 位二进制对应一个字符，请还原文本。

## 操作
字节转换工具选择二进制字节解码。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes(int(x, 2) for x in data.split()).decode())
```

## 结果与复盘
flag{binary_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
