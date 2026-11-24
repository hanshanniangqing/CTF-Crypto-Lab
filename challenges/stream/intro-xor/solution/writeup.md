# 已知单字节密钥 XOR

## 思路
密文以 Hex 保存；密钥是十六进制 2a。将每个密文字节与 0x2a 异或。

## 操作
手动 XOR 工具中密文与密钥均选 Hex；密钥填 2a。

## 参考脚本
在附件目录执行以下脚本：

```python
from pathlib import Path
data = Path('data.txt').read_text(encoding='utf-8').strip()
print(bytes(x ^ 0x2a for x in bytes.fromhex(data)).decode())
```

## 结果与复盘
flag{xor_first_step}
解释输入的表示形式，再用相反方向的运算检查能否得到原附件。
