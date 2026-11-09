import base64,io,json
from backend.server import Handler,jobs
from backend.crypto import generate

def call(path,data=b'',options=None,origin='http://localhost:5173',headers=None):
    h=Handler.__new__(Handler);h.path=path;h.headers={'Origin':origin,'X-Options':base64.b64encode(json.dumps(options or {}).encode()).decode(),'Content-Length':str(len(data))};h.headers.update(headers or {});h.rfile=io.BytesIO(data);h.wfile=io.BytesIO();h.send=lambda status,payload:setattr(h,'result',(status,payload));h.do_POST();return h.result

def test_generate_api():
    status,d=call('/api/key',options={'algorithm':'DES','bits':64});assert status==200;assert len(base64.b64decode(d['key']))==8

def test_origin_rejected():assert call('/api/key',origin='https://example.com')[0]==403

def test_missing_key():assert call('/api/transform',options={})[0]==400

def test_api_roundtrip():
    key=base64.b64encode(generate('DES')).decode();data=b'image data'*20
    status,r=call('/api/transform',data,{'key':key,'extension':'.png','implementation':'library'});assert status==200
    enc=jobs.pop(r['id'])[0];status,r2=call('/api/transform',enc.read_bytes(),{'key':key,'decrypt':True,'implementation':'library','extension':'.enc'});assert status==200
    out=jobs.pop(r2['id'])[0];assert out.read_bytes()==data;assert r2['name']=='restored.png';enc.unlink();out.unlink()
