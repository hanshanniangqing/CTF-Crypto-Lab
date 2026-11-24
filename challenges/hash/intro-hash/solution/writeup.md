# 有限候选 SHA-256 匹配

## 思路
附件第一行是 SHA-256 摘要，其余行是候选口令。找到命中的口令，提交 flag{口令}。

## 操作
依次计算候选词的 SHA-256；不要把行末换行加入口令。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
import hashlib
lines = data.splitlines()
for word in lines[1:]:
    if hashlib.sha256(word.encode()).hexdigest() == lines[0]:
        print('flag{' + word + '}')
```

## 结果与复盘
flag{sunshine}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
