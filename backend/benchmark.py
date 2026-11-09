"""Reproducible measurements in fresh processes; no fabricated results."""
import argparse,csv,json,platform,statistics,subprocess,sys,tempfile,os
from pathlib import Path
from .files import transform
from .crypto import generate

def worker(args):
    # Each measurement gets an independent RSS high-water mark.
    p=json.loads(args);key=bytes.fromhex(p.pop('key'));print(json.dumps(transform(key=key,**p)))

def main():
    p=argparse.ArgumentParser(description='DES benchmark (own Python on 101 MiB can take hours)')
    p.add_argument('--sizes',nargs='+',type=float,default=[1,10,101]);p.add_argument('--runs',type=int,default=5)
    p.add_argument('--implementations',nargs='+',choices=['own','library'],default=['own','library'])
    p.add_argument('--algorithms',nargs='+',choices=['DES'],default=['DES']);p.add_argument('--modes',nargs='+',choices=['ECB','CBC'],default=['ECB','CBC'])
    p.add_argument('--buffers',nargs='+',type=int,default=[65536]);p.add_argument('--workers',nargs='+',type=int,default=[1,2]);p.add_argument('--output',default='benchmark-results')
    args=p.parse_args()
    if args.runs<5:p.error('At least 5 runs are required')
    if any(x<=0 for x in args.sizes):p.error('Sizes must be positive')
    root=Path(args.output);root.mkdir(exist_ok=True,parents=True)
    import psutil
    environment=dict(platform=platform.platform(),python=sys.version,cpu=platform.processor(),logical_cpus=os.cpu_count(),physical_cpus=psutil.cpu_count(logical=False),ram_bytes=psutil.virtual_memory().total,runs=args.runs,memory='Fresh-process maximum RSS; parallel child peaks reported separately',io='Total minus crypto includes preparation, hash pass and pool lifecycle')
    (root/'environment.json').write_text(json.dumps(environment,indent=2));rows=[]
    with tempfile.TemporaryDirectory() as directory:
        d=Path(directory)
        for fmt in ('BMP','PNG','JPEG'):
            for size in args.sizes:
                # Real decodable images; PNG/JPEG use random pixels to avoid tiny compressed files.
                from PIL import Image
                import math
                side=math.ceil(math.sqrt(size*1048576/3));src=d/('input.'+fmt.lower());Image.frombytes('RGB',(side,side),os.urandom(side*side*3)).save(src,format=fmt,**({'quality':100,'subsampling':0} if fmt=='JPEG' else {}))
                # Ensure the requested size (including >100 MiB) with an ignored image trailer.
                missing=max(0,int(size*1048576)-src.stat().st_size)
                with open(src,'ab') as f:
                    while missing:
                        n=min(missing,65536);f.write(os.urandom(n));missing-=n
                for a in args.algorithms:
                    key=generate(a)
                    for m in args.modes:
                        for impl in args.implementations:
                            for buf in args.buffers:
                                for count in args.workers:
                                    for dec in (False,True):
                                        if count>1 and (m=='CBC' and not dec):continue
                                        enc=d/'data.enc';out=d/'restored';params=dict(algorithm=a,mode=m,padding='PKCS7',implementation=impl,buffer=buf,workers=count)
                                        if dec:transform(src,enc,key,**{**params,'workers':1})
                                        results=[]
                                        for _ in range(args.runs):
                                            job=dict(source=str(enc if dec else src),target=str(out if dec else enc),key=key.hex(),decrypt=dec,**params)
                                            r=subprocess.run([sys.executable,'-m','backend.benchmark','--worker'],input=json.dumps(job),capture_output=True,text=True,check=True);results.append(json.loads(r.stdout))
                                        times=[r['total_seconds'] for r in results];crypt=[r['crypto_seconds'] for r in results]
                                        row=dict(format=fmt,bytes=src.stat().st_size,algorithm=a,mode=m,implementation=impl,operation='decrypt' if dec else 'encrypt',workers=count,buffer=buf,runs=args.runs,total_median=statistics.median(times),total_min=min(times),total_max=max(times),crypto_median=statistics.median(crypt),crypto_min=min(crypt),crypto_max=max(crypt),io_median=statistics.median(r['io_seconds'] for r in results),mb_s=src.stat().st_size/1048576/statistics.median(crypt),peak_mb=max(r['peak_mb'] for r in results));rows.append(row)
                                        with open(root/'results.csv','w',newline='') as f:
                                            writer=csv.DictWriter(f,fieldnames=list(row));writer.writeheader();writer.writerows(rows)
                                        print(f"{fmt} {size} MiB {a}/{m} {impl} {row['operation']} p={count}: {row['total_median']:.3f}s",flush=True)
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--worker':worker(sys.stdin.read())
    else:main()
