"""Compile the production panel and measure the pixel result. Optional native previews."""
from pathlib import Path
import argparse,struct,zlib,binascii,subprocess,tempfile
here=Path(__file__).resolve().parent
src=here.parents[1]/'source'
arg=argparse.ArgumentParser(description=__doc__)
arg.add_argument('--preview-dir',type=Path);args=arg.parse_args()
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);exe=d/'probe.exe'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-pedantic',
                    '-I'+str(src),'-I'+str(here.parent/'stub'),str(here/'probe.c'),
                    str(src/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
    paths=[d/(n+'.rgb') for n in ('classic-2x','jetbrains-1x')] if args.preview_dir else []
    subprocess.run([exe,*paths],check=True)
    for raw in paths:
        args.preview_dir.mkdir(parents=True,exist_ok=True)
        rgb=raw.read_bytes();assert len(rgb)==960*544*3
        rows=b''.join(b'\0'+rgb[y*2880:(y+1)*2880] for y in range(544))
        def chunk(k,b):return struct.pack('>I',len(b))+k+b+struct.pack('>I',binascii.crc32(k+b)&0xffffffff)
        image=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',960,544,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(rows))+chunk(b'IEND',b'')
        out=args.preview_dir/('host-'+raw.stem+'.png');out.write_bytes(image);assert out.read_bytes()==image
        print('host-render preview:',out.resolve())
