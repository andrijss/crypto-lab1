import os,json,hashlib,zipfile
from pathlib import Path
import pytest
from Crypto.Cipher import DES as RefDES
from backend.crypto import DES,Mode,generate,pad,unpad,key_check
from backend.files import transform,read_header
from backend.tables import load
from backend.images import pixels

def test_des_vector():
    a=DES(bytes.fromhex('133457799BBCDFF1'));p=bytes.fromhex('0123456789ABCDEF');assert a.encrypt(p).hex()=='85e813540f0ab405';assert a.decrypt(a.encrypt(p))==p

@pytest.mark.parametrize('a,m,p', [('DES',m,p) for m in ('ECB','CBC') for p in ('PKCS7','PKCS5','X923')])
@pytest.mark.parametrize('n',[0,1,7,8,15,16,17,64,71])
def test_roundtrip_reference(tmp_path,a,m,p,n):
    key=generate(a);iv=os.urandom(8) if m!='ECB' else b'';data=os.urandom(n);bs=8
    plain=pad(data,bs,p)
    own=Mode(key,a,m,iv);lib=Mode(key,a,m,iv,'library')
    ct=own.update(plain);assert ct==lib.update(plain)
    source=tmp_path/'image.png';source.write_bytes(data);enc=tmp_path/'image.enc';out=tmp_path/'out'
    transform(source,enc,key,a,m,p,buffer=32);transform(enc,out,key,buffer=32,decrypt=True);assert out.read_bytes()==data

@pytest.mark.parametrize('m',['ECB','CBC'])
@pytest.mark.parametrize('field',['ciphertext','iv','checksum','key'])
def test_tamper_atomic(tmp_path,m,field):
    src=tmp_path/'src.png';src.write_bytes(b'abc'*53);enc=tmp_path/'enc';out=tmp_path/'out';key=generate('DES');transform(src,enc,key,mode=m,padding='PKCS7')
    b=bytearray(enc.read_bytes())
    if field in ('iv','checksum'):
        if m=='ECB' and field=='iv':return
        hlen=int.from_bytes(b[5:9],'big');h=json.loads(b[9:9+hlen]);name='iv' if field=='iv' else 'sha256';h[name]=('1' if h[name][0]!='1' else '2')+h[name][1:];raw=json.dumps(h,sort_keys=True,separators=(',',':')).encode();b[9:9+hlen]=raw
    elif field=='ciphertext':b[-20]^=1
    else:key=generate('DES')
    enc.write_bytes(b)
    with pytest.raises(ValueError):transform(enc,out,key,decrypt=True)
    assert not out.exists();out.write_bytes(b'keep')
    with pytest.raises(ValueError):transform(enc,out,key,decrypt=True)
    assert out.read_bytes()==b'keep';assert not list(tmp_path.glob('.cryptolab-*'))

@pytest.mark.parametrize('p',['PKCS7','PKCS5','X923'])
def test_padding(p):
    for n in range(25):
        d=os.urandom(n);assert unpad(pad(d,8,p),8,p)==d
    with pytest.raises(ValueError):unpad(b'1234567\0',8,p)

def test_key_and_tables(tmp_path):
    for a in ('DES',):
        with pytest.raises(ValueError):key_check(b'bad',a)
        key_check(generate(a),a)
    with pytest.raises(ValueError):key_check(bytes(8),'DES')
    d=json.loads(Path('backend/des_tables.json').read_text());d['IP'][0]=d['IP'][1];p=tmp_path/'tables';p.write_text(json.dumps(d))
    with pytest.raises(ValueError):load(p)

@pytest.mark.parametrize('fmt',['PNG','BMP','JPEG'])
def test_images(tmp_path,fmt):
    from PIL import Image
    src=tmp_path/('image.'+fmt.lower());Image.new('RGB',(33,29),(80,20,190)).save(src,format=fmt);key=generate('DES');enc=tmp_path/'enc';out=tmp_path/'out'
    transform(src,enc,key,implementation='library');transform(enc,out,key,implementation='library',decrypt=True);assert src.read_bytes()==out.read_bytes()
    z=tmp_path/'demo.zip';png=tmp_path/'restored.png';pixels(src,z,key,mode='CBC',padding='PKCS7');pixels(z,png,key,decrypt=True)
    with Image.open(src) as a,Image.open(png) as b:assert a.convert('RGB').tobytes()==b.tobytes()
    with zipfile.ZipFile(z) as archive:
        with archive.open('encrypted.png') as f,Image.open(f) as image:assert image.size==(33,29)

@pytest.mark.parametrize('m,dec',[('ECB',False),('ECB',True),('CBC',True)])
def test_parallel(tmp_path,m,dec):
    src=tmp_path/'src';src.write_bytes(os.urandom(193));enc=tmp_path/'enc';out=tmp_path/'out';key=generate('DES');transform(src,enc,key,mode=m,padding='PKCS7',workers=1 if dec else 2,buffer=32);transform(enc,out,key,decrypt=True,workers=2 if dec else 1,buffer=32);assert src.read_bytes()==out.read_bytes()

def test_large(tmp_path):
    src=tmp_path/'large.bmp';chunk=os.urandom(1048576)
    with open(src,'wb') as f:
        for _ in range(101):f.write(chunk)
    key=generate('DES');enc=tmp_path/'enc';out=tmp_path/'out'
    stats=transform(src,enc,key,implementation='library');transform(enc,out,key,implementation='library',decrypt=True)
    def digest(p):
        h=hashlib.sha256()
        with open(p,'rb') as f:
            while b:=f.read(65536):h.update(b)
        return h.digest()
    assert src.stat().st_size>100*1048576;assert digest(src)==digest(out);assert stats['buffer']==65536
