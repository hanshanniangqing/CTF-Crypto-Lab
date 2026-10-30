# md5-collision — 题解

> hash / 入门 / 100 分 / 考点: MD5 碰撞 (前缀碰撞性质)

## 漏洞点
MD5 采用 Merkle-Damgård 结构：只要两个消息在某一块后内部链值 (chaining
value) 相同，其后续哈希就永远相同。lib/data 提供的 128 字节碰撞块对 (A, B)
满足 MD5(A)=MD5(B) 且等长，因此在两者后面追加**完全相同的任意尾巴**，
MD5 仍碰撞；而 SHA256 会立刻分开。由此可以构造"MD5 相同、内容与 SHA256
都不同"的合法文件对——数字取证与完整性校验的灾难。

## 利用思路
1. 读附件 colliding_base_1.bin / colliding_base_2.bin（由 A、B 加同一尾巴构成）。
2. 给两者再追加一段相同的后缀（使长度超过 200 字节，绕开长度检查）。
3. 分别写入 good.bin（以 base1 开头）与 evil.bin（以 base2 开头）。
4. 运行 verify.py：MD5 相同 + SHA256 不同 + 前缀正确 → 打印 flag。

## 关键代码
suffix = b"\napproved: yes\n" + b"-" * 64
open("good.bin", "wb").write(base1 + suffix)
open("evil.bin", "wb").write(base2 + suffix)
out = subprocess.run([sys.executable, "verify.py"],
                     capture_output=True, text=True).stdout
print(out.strip())

## 防御建议
- 任何安全用途（签名、去重、完整性）禁用 MD5，改用 SHA-256 或 SHA-3。
- 历史系统应盘点 MD5 依赖：数字取证、合同存证、软件签名都可能被碰撞文件替换。
- 需要前缀选择安全 (chosen-prefix) 防护时使用更强的哈希或对整份文件二次签名。
