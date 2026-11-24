"""起步题、工具向量与两个 Web API 的回归验证。"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import learning
import beginner_tools as B
import webconsole as W
import toolkit_web as T

class LearningTests(unittest.TestCase):
    def test_attachments_solve(self):
        for c in W._index().values():
            if not c.get('beginner_order'):
                continue
            with self.subTest(name=c['name']), tempfile.TemporaryDirectory() as tmp:
                root = ROOT/'challenges'/c['category']/c['name']
                shutil.copy(root/'src/data.txt', tmp)
                out = subprocess.check_output([sys.executable, str(root/'solution/solve.py')], cwd=tmp, text=True, encoding='utf-8')
                self.assertEqual(out.strip(), c['flag'])

    def test_known_vectors(self):
        for radix, data in [('2','01001000 01101001'),('10','72 105'),('16','48 69')]:
            self.assertEqual(B.bytes_tool(dict(radix=radix,data=data))['result'], 'Hi')
            encoded=B.bytes_tool(dict(radix=radix,data='中文',mode='enc'))['result']
            self.assertEqual(B.bytes_tool(dict(radix=radix,data=encoded))['result'],'中文')
        self.assertEqual(B.atbash({'data':'Hello!'})['result'],'Svool!')
        self.assertEqual(B.bacon({'data':'AABBB AABAA ABABB ABABB ABBBA'})['result'],'HELLO')
        self.assertEqual(B.xor_manual(dict(data='624f464645',key='2a'))['result'],'Hello')
        f=dict(T.EXAMPLES['aes'])
        self.assertIn(('Hex','00112233445566778899aabbccddeeff'),B.aes(f)['extras'])
        f.update(mode='enc',data='00112233445566778899aabbccddeeff')
        self.assertEqual(B.aes(f)['result'],'69c4e0d86a7b0430d8cdb78070b4c55a')
        f.update(cipher_mode='CBC',padding='pkcs7',iv='00'*16,data='你好，CTF',format='text')
        ct=B.aes(f)['result']
        f.update(mode='dec',data=ct,format='hex')
        self.assertEqual(B.aes(f)['result'],'你好，CTF')
        self.assertEqual(T.t_railfence(dict(mode='enc',rails='3',data='WEAREDISCOVEREDFLEEATONCE'))['result'],'WECRLTEERDSOEEFEAOCAIVDEN')

    def test_invalid_inputs(self):
        for fn, f in [(B.bytes_tool,dict(radix='2',data='011')),(B.bytes_tool,dict(data='256')),
                      (B.bacon,dict(data='BBBBB')),(B.xor_manual,dict(data='ff',key='')),
                      (B.aes,dict(key='00')),(B.frequency,dict(data='123'))]:
            with self.subTest(fn=fn.__name__), self.assertRaises(ValueError):
                fn(f)

    def test_examples(self):
        for name, fields in T.EXAMPLES.items():
            with self.subTest(tool=name):
                self.assertTrue(T.TOOL_MAP[name]['fn'](fields)['ok'])

    def test_http(self):
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for handler in (W.Handler,T.Handler):
            server=ThreadingHTTPServer(('127.0.0.1',0),handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            url='http://127.0.0.1:'+str(server.server_port)
            def get(path):
                with opener.open(url+path) as r:
                    return json.load(r)
            try:
                if handler is W.Handler:
                    challenges=get('/api/index')['challenges']
                    self.assertEqual(len(challenges),52)
                    for c in challenges:
                        self.assertNotIn('flag',c)
                        self.assertIn('本题要掌握',c['knowledge']['markdown'])
                        self.assertIn(c['knowledge']['tool'],T.TOOL_MAP)
                    self.assertEqual(sum(bool(c['beginner_order']) for c in challenges),8)
                    self.assertIn('先记住四件事',get('/api/learn')['markdown'])
                    self.assertTrue(get('/api/material/intro-hex')['files'])
                else:
                    tools=get('/api/tools')['tools']
                    self.assertEqual(len(tools),44)
                    self.assertTrue(all('参数怎么填' in t['guide'] for t in tools))
                    req=urllib.request.Request(url+'/api/tool/xor-manual',data=json.dumps(T.EXAMPLES['xor-manual']).encode(),headers={'Content-Type':'application/json'})
                    with opener.open(req) as r:
                        self.assertEqual(json.load(r)['result'],'Hello')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

if __name__ == '__main__':
    unittest.main()
