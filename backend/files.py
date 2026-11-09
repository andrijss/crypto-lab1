"""Streaming container. All output commits atomically after validation."""
import os,json,struct,tempfile,hashlib,time,secrets,resource,sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from .crypto import Mode,key_check,pad,unpad
MAGIC=b'CLAB\x01'

def validate(a,m,p,b,w):
    if a != 'DES' or m not in ('ECB','CBC'):raise ValueError('Unsupported algorithm / mode')
    if p not in ('PKCS7','PKCS5','X923'):raise ValueError('Unsupported padding')
    if type(b)!=int or not 8<=b<=16*1024*1024 or b%8:raise ValueError('Buffer must be 8–16777216 bytes and a multiple of 8')
    if type(w)!=int or not 1<=w<=8:raise ValueError('Process count must be 1–8')

def read_header(f):
    if f.read(5)!=MAGIC:raise ValueError('Unknown container signature or version')
    raw=f.read(4)
    if len(raw)!=4:raise ValueError('Truncated container')
    n=struct.unpack('>I',raw)[0]
    if not 1<=n<=65536:raise ValueError('Invalid header')
    data=f.read(n)
    if len(data)!=n:raise ValueError('Truncated header')
    h=json.loads(data)
    if set(h)!={'algorithm','mode','padding','iv','length','type','sha256'}:raise ValueError('Invalid metadata')
    if type(h['length'])!=int or h['length']<0 or not isinstance(h['type'],str) or len(h['type'])>32:raise ValueError('Invalid length / type')
    if not isinstance(h['sha256'],str) or len(bytes.fromhex(h['sha256']))!=32:raise ValueError('Invalid checksum')
    return h,MAGIC+raw+data

def task(args):
    key,a,m,iv,impl,dec,data=args
    return Mode(key,a,m,iv,impl,dec).update(data)

def transform(source,target,key,algorithm='DES',mode='CBC',padding='PKCS7',implementation='own',buffer=65536,workers=1,decrypt=False,progress=None):
    report=progress or (lambda *args: None)
    start=time.perf_counter();crypto_time=0; key_check(key,algorithm) if not decrypt else None
    validate(algorithm,mode,padding,buffer,workers)
    digest=hashlib.sha256();size=os.path.getsize(source);pool=None;tmp=None
    try:
        with open(source,'rb') as src:
            if decrypt:
                h,header=read_header(src);algorithm,mode,padding=h['algorithm'],h['mode'],h['padding'];validate(algorithm,mode,padding,buffer,workers);key_check(key,algorithm);iv=bytes.fromhex(h['iv']);length=h['length'];offset=src.tell();size-=offset
            else:
                # Separate pass supplies a byte-exact recovery checksum for non-AEAD modes.
                report('preparing',0,size)
                while chunk:=src.read(buffer):
                    digest.update(chunk);report('preparing',src.tell(),size)
                src.seek(0);length=size;iv=secrets.token_bytes(8) if mode!='ECB' else b''
                h=dict(algorithm=algorithm,mode=mode,padding=padding,iv=iv.hex(),length=length,type=Path(source).suffix.lower()[:32],sha256=digest.hexdigest())
                data=json.dumps(h,sort_keys=True,separators=(',',':')).encode();header=MAGIC+struct.pack('>I',len(data))+data
            bs=8
            expected=(length//bs+1)*bs
            if decrypt and size!=expected:raise ValueError('Invalid ciphertext length')
            if workers>1 and (mode=='CBC' and not decrypt):raise ValueError('Parallel processing is available for ECB and CBC decryption')
            t=time.perf_counter();cipher=Mode(key,algorithm,mode,iv,implementation,decrypt);crypto_time+=time.perf_counter()-t
            if workers>1:pool=ProcessPoolExecutor(workers)
            fd,tmp=tempfile.mkstemp(prefix='.cryptolab-',dir=Path(target).parent);digest=hashlib.sha256();written=0
            with os.fdopen(fd,'wb') as dst:
                if not decrypt:dst.write(header)
                remaining=expected if decrypt else length;last=b'';previous=iv
                processing_total=remaining;phase='decrypting' if decrypt else 'encrypting'
                report(phase,0,processing_total)
                while remaining:
                    jobs=[]
                    for _ in range(workers if pool else 1):
                        if not remaining:break
                        chunk=src.read(min(buffer,remaining));remaining-=len(chunk)
                        if not chunk:raise ValueError('Truncated data')
                        if not decrypt and not remaining:chunk=pad(chunk,bs,padding)
                        jobs.append((key,algorithm,mode,previous,implementation,decrypt,chunk))
                        if mode=='CBC' and decrypt:previous=chunk[-bs:]
                    t=time.perf_counter()
                    results=list(pool.map(task,jobs)) if pool else [cipher.update(jobs[0][-1])]
                    crypto_time+=time.perf_counter()-t
                    for result in results:
                        if decrypt:
                            data=last+result;last=data[-bs:];result=data[:-bs]
                        dst.write(result);written+=len(result)
                        if decrypt:digest.update(result)
                    report(phase,processing_total-remaining,processing_total)
                report('verifying',0,1)
                if not decrypt and length%bs==0 and length==0:
                    t=time.perf_counter();dst.write(cipher.update(pad(b'',bs,padding)));crypto_time+=time.perf_counter()-t
                if decrypt:
                    t=time.perf_counter();result=unpad(last,bs,padding);crypto_time+=time.perf_counter()-t;dst.write(result);digest.update(result);written+=len(result)
                if decrypt and (written!=length or digest.hexdigest()!=h['sha256']):raise ValueError('File is corrupted or the key is incorrect')
            os.replace(tmp,target);tmp=None
        elapsed=time.perf_counter()-start
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/(1024*1024 if sys.platform=='darwin' else 1024)
        return dict(total_seconds=elapsed,crypto_seconds=crypto_time,io_seconds=max(0,elapsed-crypto_time),mb_s=length/1048576/crypto_time if crypto_time else 0,peak_mb=rss,workers=workers,buffer=buffer,bytes=length,verified=decrypt,**{'algorithm':algorithm,'mode':mode,'padding':padding})
    finally:
        if pool:pool.shutdown()
        if tmp:os.unlink(tmp)
