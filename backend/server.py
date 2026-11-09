"""Local-only HTTP API: bounded upload reads, opaque download IDs, no key logs."""
import base64,json,tempfile,uuid,os,shutil,threading,zipfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlparse
from .files import transform
from .images import pixels
from .crypto import generate
from . import progress
ROOT=Path(tempfile.mkdtemp(prefix='cryptolab-'));jobs={};lock=threading.Lock()
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,data):
        b=json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self):
        path=urlparse(self.path).path
        if path.startswith('/api/progress/'):
            state=progress.snapshot(path.removeprefix('/api/progress/'))
            return self.send(200,state) if state else self.send(404,{'error':'Progress not found'})
        preview=path.startswith('/api/preview/')
        ident=path.removeprefix('/api/preview/' if preview else '/api/download/')
        if ident not in jobs:return self.send(404,{'error':'File not found'})
        p,name=jobs[ident]
        if preview:
            if name!='pixels.zip':return self.send(400,{'error':'Preview unavailable'})
            with zipfile.ZipFile(p) as z:
                self.send_response(200);self.send_header('Content-Type','image/png');self.send_header('Content-Length',str(z.getinfo('encrypted.png').file_size));self.end_headers()
                with z.open('encrypted.png') as f:shutil.copyfileobj(f,self.wfile,65536)
            return
        self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Content-Length',str(p.stat().st_size));self.send_header('Content-Disposition',f'attachment; filename="{name}"');self.end_headers()
        with open(p,'rb') as f:shutil.copyfileobj(f,self.wfile,65536)
    def do_POST(self):
        # Vite forwards same-origin browser requests. Reject foreign browser origins.
        origin=self.headers.get('Origin','')
        if origin and origin not in ('http://localhost:5173','http://127.0.0.1:5173'):return self.send(403,{'error':'Request origin is not allowed'})
        source=None;progress_id=None
        try:
            options=json.loads(base64.b64decode(self.headers.get('X-Options','e30='),validate=True))
            if self.path=='/api/key':return self.send(200,{'key':base64.b64encode(generate(options['algorithm'],options.get('bits',64))).decode()})
            if self.path!='/api/transform':return self.send(404,{'error':'Unknown request'})
            n=int(self.headers.get('Content-Length','-1'))
            if not 0<=n<=10*1024**3:raise ValueError('Maximum file size: 10 GiB')
            candidate=options.pop('progress_id',self.headers.get('X-Progress-ID'))
            if candidate is not None:
                progress.start(candidate);progress_id=candidate
            upload_total=n
            ident=uuid.uuid4().hex;source=ROOT/(ident+options.pop('extension','.bin') if options.get('extension') in ('.png','.bmp','.jpg','.jpeg','.enc','.zip') else ident+'.bin')
            with open(source,'wb') as f:
                while n:
                    b=self.rfile.read(min(n,65536))
                    if not b:raise ValueError('Upload interrupted')
                    f.write(b);n-=len(b)
                    if progress_id:progress.update(progress_id,'uploading',upload_total-n,upload_total)
            options.pop('extension',None);key=base64.b64decode(options.pop('key'),validate=True);demo=options.pop('demo',False);dec=options.get('decrypt',False)
            if progress_id:
                progress.update(progress_id,'preparing')
                options['progress']=lambda phase,done,total:progress.update(progress_id,phase,done,total)
            target=ROOT/(ident+'.result');stats=(pixels if demo else transform)(source,target,key,**options)
            name='restored.png' if demo and dec else 'pixels.zip' if demo else 'restored'+self.original_extension(source) if dec else 'image.enc'
            jobs[ident]=(target,name)
            if progress_id:progress.update(progress_id,'completed')
            timer=threading.Timer(3600,lambda:(jobs.pop(ident,None),target.unlink(missing_ok=True)));timer.daemon=True;timer.start()
            self.send(200,dict(id=ident,name=name,stats=stats))
        except Exception as e:
            if progress_id:progress.update(progress_id,'failed')
            self.send(400,{'error':str(e) or 'Unable to process file'})
        finally:
            if source:source.unlink(missing_ok=True)
    def original_extension(self,source):
        from .files import read_header
        with open(source,'rb') as f:h,_=read_header(f)
        return h['type'] if h['type'] in ('.png','.bmp','.jpg','.jpeg') else '.bin'
if __name__=='__main__':
    print('Crypto Lab API: http://127.0.0.1:8000')
    try:ThreadingHTTPServer(('127.0.0.1',8000),Handler).serve_forever()
    finally:shutil.rmtree(ROOT,ignore_errors=True)
