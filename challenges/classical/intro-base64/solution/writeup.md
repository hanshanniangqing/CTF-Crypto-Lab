# 单层 Base64 解码

## 思路
附件只经过一次 Base64 编码，请还原文本。

## 操作
Base 工具选择 Base64 与解码。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import base64
print(base64.b64decode(data).decode())
```

## 结果与复盘
flag{base64_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
