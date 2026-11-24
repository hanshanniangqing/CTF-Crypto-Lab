"""按工具提供原理、字段约定、操作流程和常见错误。"""
from learning import PROFILES, FOUNDATIONS

SPECIAL = {
    'url': 'URL 百分号编码用 % 后的两位 Hex 表示字节，例如 %41 → A。粘贴原始编码文本并运行；本工具保留 +，不会把它当表单空格。',
    'morse': '摩斯电码用点和划表示字符；本工具用空格分隔字母，用 / 分隔单词。例如 .... .. / -.-. - ..-. → HI CTF。',
    'railfence': 'W 型栅栏按上下折返轨迹写入字符，逐栏读出；解密要先恢复每栏长度。栏数至少为 2，空格也参与排列。',
    'xor-single': '单字节密钥只有 256 种，逐个异或后以英文评分排序。输入格式默认 Hex；短文本或非英文输出应人工检查其他候选。',
    'xor-two': '两条密文逐位异或可消去相同密钥流，得到两段明文的异或。它不会直接给出任一原文；两份数据应从相同密钥流位置开始。',
    'rsa-basic': '已知 p、q 后计算 φ=(p−1)(q−1)、d=e 的模 φ 逆元，再求 m=c^d mod pq。要求 p、q 为不同素数且 e 与 φ 互素；输出按大端字节解释。',
    'nt': 'gcd 求最大公约数；modinv 求模逆元（要求互素）；powmod 计算 a^b mod c；iroot 求整数根。bytes2int/int2bytes 采用大端表示，整数转换会丢失原始前导零。先在操作下拉框选运算，再填相关参数。',
    'atbash': '用镜像字母替换：A↔Z、B↔Y，保留大小写与其他字符。加密与解密使用同一操作，例如 HELLO → SVOOL。',
    'bacon': '使用 26 字母版本，以 A/B 表示 0/1，每 5 位一组，从 A=AAAAA 到 Z=BBAAB；与合并 I/J、U/V 的 24 字母版本不同。单词使用 / 分隔，编码仅接受英文字母与空格。',
    'frequency': '只统计英文字母，IC=Σ n_i(n_i−1)/(N(N−1))。英文文本常在 0.065 附近，均匀随机字母约 0.038；样本很短时不要据此下结论。',
    'aes': FOUNDATIONS['symmetric'] + ' 先选方向、模式与填充，再填输入、密钥及其格式；CBC 需要 16 字节 IV（32 个 Hex 字符）。加密输出 Hex，解密时密文格式选 Hex。PKCS#7 错误通常表示参数不匹配。ECB/CBC 本身不提供认证。',
    'xor-manual': '按字节异或，密钥短于数据时循环使用。选择文本或 Hex 后再填值；文本密钥 2a 是两个字节，Hex 密钥 2a 是一个字节。再次使用同一密钥可还原。',
}

GROUP_CAT = {'编码':'classical','古典':'classical','XOR':'stream','哈希':'hash','数论/RSA':'rsa','离散对数':'pubkey','PRNG':'stream','格':'lattice','对称密码':'symmetric'}

def guide(t):
    parts = [p[0] + ' ' + p[1] for p in PROFILES.values() if p[2] == t['id']]
    principle = SPECIAL.get(t['id']) or '\n\n'.join(dict.fromkeys(parts)) or t['desc']
    fields = '\n'.join('- ' + f['label'] + '：' + (f.get('help') or (
        '从下拉选项选择：' + '、'.join(o['l'] for o in f['options']) if f.get('options') else
        '按字段标注的格式填写；Hex 按两位一个字节，整数默认十进制，十六进制整数请加 0x 前缀。')) for f in t['fields'])
    return ('## 入门知识\n' + FOUNDATIONS[GROUP_CAT[t['group']]] +
            '\n\n## 本工具原理\n' + principle + '\n\n## 参数怎么填\n' + fields +
            '\n\n## 使用步骤\n1. 核对输入属于文本、Hex 字节还是整数，选择操作方向。\n'
            '2. 有“填入示例”时先运行独立示例，再换成自己的材料。\n'
            '3. 点击运行，阅读主输出、附加信息与步骤；不可打印的字节优先查看 Hex。\n'
            '4. 用正向运算、另一组样本或题目验证器检查结果。\n\n'
            '## 常见问题\n文本末尾换行会改变摘要和加密结果；Hex 字节需要偶数位；只有数字的整数字段按十进制解析。'
            '破解类工具可能只给出候选或在参数不满足时失败。ZipCrypto、SSH 私钥、sha512crypt 需使用 John 等对应格式工具，本地摘要字典工具不能替代这些格式。')
