# Hex 字节与文本

## 思路
把附件中的十六进制解码一次，找到 flag。

## 操作
Hex 每两位是一字节，选择 Hex 工具的解码方向。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes.fromhex(data).decode())
```

## 结果与复盘
flag{hex_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
