import tempfile,zipfile,json
from pathlib import Path
from PIL import Image
from .files import transform

def pixels(source,target,key,decrypt=False,**options):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);raw=root/'pixels.rgb';enc=root/'pixels.enc'
        if decrypt:
            with zipfile.ZipFile(source) as z:
                if set(z.namelist())!={'encrypted.png','pixels.enc','image.json'}:raise ValueError('Invalid pixel package')
                info=json.loads(z.read('image.json'))
                with z.open('pixels.enc') as src,open(enc,'wb') as dst:
                    import shutil;shutil.copyfileobj(src,dst,65536)
            w,h=info['size']
            if type(w)!=int or type(h)!=int or w<=0 or h<=0 or w*h>25000000:raise ValueError('Invalid dimensions')
            stats=transform(enc,raw,key,decrypt=True,**options)
            if options.get('progress'):options['progress']('finalizing',0,1)
            Image.frombytes('RGB',(w,h),raw.read_bytes()).save(target,format='PNG')
        else:
            with Image.open(source) as image:
                if image.width*image.height>25000000:raise ValueError('Pixel demo: maximum 25 million pixels; use file mode for larger files')
                image=image.convert('RGB');raw.write_bytes(image.tobytes());size=image.size
            stats=transform(raw,enc,key,**options)
            if options.get('progress'):options['progress']('finalizing',0,1)
            from .files import read_header
            with open(enc,'rb') as f:
                read_header(f);data=f.read(len(raw.read_bytes()))
            preview=root/'encrypted.png';Image.frombytes('RGB',size,data).save(preview)
            with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_STORED) as z:
                z.write(enc,'pixels.enc');z.write(preview,'encrypted.png');z.writestr('image.json',json.dumps({'size':size,'mode':'RGB'}))
        return stats
