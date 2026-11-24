"""工具箱的基础工具，保持独立以便直接验证和复用。"""
from collections import Counter
import re

def result(value, steps, extras=None):
    return dict(ok=True, result=value, steps=steps, extras=extras or [], elapsed=0)

def byte_input(data, fmt):
    if fmt == 'hex':
        return bytes.fromhex(data)
    return data.encode('utf-8')

def bytes_tool(f):
    data, mode = f.get('data', ''), f.get('mode', 'dec')
    radix = int(f.get('radix', '10'))
    if radix not in (2, 10, 16):
        raise ValueError('只支持二进制、十进制和十六进制')
    if mode == 'enc':
        raw = data.encode('utf-8')
        out = ' '.join(format(x, '08b' if radix == 2 else '02x') if radix != 10 else str(x) for x in raw)
    else:
        parts = data.split()
        if radix == 2 and len(parts) == 1:
            if len(parts[0]) % 8:
                raise ValueError('连续二进制长度必须为 8 的倍数')
            parts = [data[i:i+8] for i in range(0, len(data), 8)]
        if radix == 2 and any(not re.fullmatch('[01]{8}', x) for x in parts):
            raise ValueError('二进制每组必须恰好 8 位')
        raw = bytes(int(x, radix) for x in parts)
        out = raw.decode('utf-8', errors='replace')
    return result(out, ['按指定进制解析每个字节，取值 0～255。', '文本按 UTF-8 编解码；无法显示的字节请检查附加 Hex。'], [('Hex', raw.hex()), ('字节数', len(raw))])

def atbash(f):
    s = f.get('data', '')
    out = ''.join(chr(ord('a')+ord('z')-ord(c)) if 'a'<=c<='z' else chr(ord('A')+ord('Z')-ord(c)) if 'A'<=c<='Z' else c for c in s)
    return result(out, ['A↔Z、B↔Y，保留大小写及非英文字母。', '同一变换执行两次还原原文。'])

def bacon(f):
    s = f.get('data', '').upper()
    if f.get('mode', 'dec') == 'enc':
        if any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ' for c in s):
            raise ValueError('培根示例仅支持 A～Z 和空格')
        out = ' / '.join(' '.join(format(ord(c)-65, '05b').translate(str.maketrans('01','AB')) for c in word) for word in s.split())
    else:
        words = []
        for word in s.split('/'):
            chars = re.sub(r'\s+', '', word)
            if len(chars)%5 or re.search('[^AB]',chars):
                raise ValueError('每个字母需要 5 个 A/B，单词用 / 分隔')
            nums = [int(chars[i:i+5].translate(str.maketrans('AB','01')),2) for i in range(0,len(chars),5)]
            if any(n>25 for n in nums):
                raise ValueError('此工具使用 26 字母版，值必须在 0～25')
            words.append(''.join(chr(65+n) for n in nums))
        out = ' '.join(words)
    return result(out, ['使用 26 字母版：A=AAAAA，B=AAAAB，Z=BBAAB。', 'A/B 分别代表二进制 0/1，每 5 位表示一个字母。'])

def frequency(f):
    counts = Counter(c for c in f.get('data','').upper() if 'A'<=c<='Z')
    total = sum(counts.values())
    if not total:
        raise ValueError('请输入至少一个英文字母')
    ic = sum(n*(n-1) for n in counts.values())/(total*(total-1)) if total>1 else 0
    return result('\n'.join(f'{c}: {n} ({100*n/total:.2f}%)' for c,n in counts.most_common()), ['忽略非英文字母并统计各字母占比。', '英文常见字母可作替代密码线索；短文本统计不稳定，频率不能直接确定映射。'], [('字母数',total),('重合指数 IC', f'{ic:.6f}')])

def xor_manual(f):
    raw = byte_input(f.get('data',''), f.get('format','hex'))
    key = byte_input(f.get('key',''), f.get('key_format','hex'))
    if not key:
        raise ValueError('密钥不能为空')
    out = bytes(x ^ key[i%len(key)] for i,x in enumerate(raw))
    return result(out.decode('utf-8', errors='replace'), ['按字节计算：输出[i] = 输入[i] XOR 密钥[i mod 密钥长度]。', '再次用同一密钥异或即可还原；不可打印输出请复制附加 Hex。'], [('Hex',out.hex())])

def aes(f):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    key = byte_input(f.get('key',''), f.get('key_format','hex'))
    if len(key) not in (16,24,32):
        raise ValueError('AES 密钥必须是 16、24 或 32 字节')
    mode = f.get('cipher_mode','CBC')
    if mode not in ('CBC','ECB'):
        raise ValueError('仅支持 CBC 或 ECB')
    iv = bytes.fromhex(f.get('iv','')) if mode=='CBC' else b''
    if mode=='CBC' and len(iv)!=16:
        raise ValueError('CBC 的 IV 必须是 16 字节 Hex')
    cipher = AES.new(key, AES.MODE_CBC, iv=iv) if mode=='CBC' else AES.new(key,AES.MODE_ECB)
    enc = f.get('mode','dec')=='enc'
    raw = byte_input(f.get('data',''), f.get('format','hex'))
    padding = f.get('padding','pkcs7')=='pkcs7'
    if enc and padding:
        raw = pad(raw,16)
    if len(raw)%16:
        raise ValueError('无填充数据或密文长度必须是 16 字节的倍数')
    out = cipher.encrypt(raw) if enc else cipher.decrypt(raw)
    if not enc and padding:
        try:
            out=unpad(out,16)
        except ValueError:
            raise ValueError('PKCS#7 校验失败，请检查密钥、IV、模式与填充设置') from None
    return result(out.hex() if enc else out.decode('utf-8', errors='replace'), ['核对密钥字节数、分组模式与 IV。', ('填充后加密，主输出为 Hex。' if enc else '解密后按设置移除填充，附加 Hex 保留原始输出。')], [('Hex',out.hex()),('字节数',len(out))])

def register(F, SEL):
    data = lambda: F('data','输入数据',type='textarea',rows=5)
    direction = lambda: SEL('mode','方向',[('dec','解码 / 解密'),('enc','编码 / 加密')],'dec')
    fmt = lambda name,label: SEL(name,label,[('hex','Hex'),('text','UTF-8 文本')],'hex')
    return [
        dict(id='bytes',group='编码',name='字节与进制转换',desc='二进制 / 十进制 / Hex 字节 ↔ UTF-8 文本',fields=[direction(),SEL('radix','进制',[('2','二进制'),('10','十进制 ASCII'),('16','十六进制')],'10'),data()],fn=bytes_tool),
        dict(id='atbash',group='古典',name='Atbash 字母镜像',desc='A↔Z、B↔Y，一次变换即可加解密',fields=[data()],fn=atbash),
        dict(id='bacon',group='古典',name='培根密码',desc='26 字母版，每 5 个 A/B 表示一个字母',fields=[direction(),data()],fn=bacon),
        dict(id='frequency',group='古典',name='字母频率与 IC',desc='统计 A～Z 频率与重合指数',fields=[data()],fn=frequency),
        dict(id='xor-manual',group='XOR',name='手动 XOR 加解密',desc='已知单字节或循环密钥，文本 / Hex 输入',fields=[data(),fmt('format','输入格式'),F('key','密钥'),fmt('key_format','密钥格式')],fn=xor_manual),
        dict(id='aes',group='对称密码',name='AES 加解密',desc='ECB / CBC，PKCS#7 或无填充',fields=[direction(),SEL('cipher_mode','分组模式',[('CBC','CBC'),('ECB','ECB')],'CBC'),data(),fmt('format','输入格式'),F('key','密钥'),fmt('key_format','密钥格式'),F('iv','CBC 的 IV（Hex，32 字符）'),SEL('padding','填充',[('pkcs7','PKCS#7'),('none','无填充')],'pkcs7')],fn=aes),
    ]
