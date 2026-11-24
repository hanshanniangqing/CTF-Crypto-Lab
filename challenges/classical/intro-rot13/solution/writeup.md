# 固定 ROT13 解密

## 思路
附件英文字母都移动了 13 位。数字、括号、下划线保持不变。

## 操作
凯撒工具选择解密，位移填 13。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import codecs
print(codecs.decode(data, 'rot_13'))
```

## 结果与复盘
flag{rot13_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
