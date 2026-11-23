"""Compile real Vita panel/font and BMP writer with standard-C file sinks. Local only."""
import argparse, binascii, hashlib, json, os, struct, subprocess, tempfile, zlib
from pathlib import Path
root=Path(__file__).resolve().parents[2]
src=root/'source'
def chunk(t,b):return struct.pack('>I',len(b))+t+b+struct.pack('>I',binascii.crc32(t+b)&0xffffffff)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--preview',type=Path,help='optional lossless host-render PNG (not a device screenshot)')
args=p.parse_args()
with tempfile.TemporaryDirectory(prefix='wb-console-') as td:
    d=Path(td);code=(src/'display.c').read_text()
    fragment=code.split('static void put32le',1)[1].split('void display_close(',1)[0]
    (d/'capture.inc').write_text('static void put32le'+fragment)
    exe=d/('test.exe' if os.name=='nt' else 'test')
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-DTEST_CAPTURE','-I',str(d),'-I',str(src),str(src/'test_title_render.c'),str(src/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],cwd=d,check=True)
    b=(d/'host-console.bmp').read_bytes();assert b[:2]==b'BM'
    assert struct.unpack_from('<iiHH',b,18)==(960,544,1,24)
    start=struct.unpack_from('<I',b,10)[0];assert len(b)==start+960*544*3
    # Decode real BGR bottom-up rows losslessly; verify the exact colour the
    # device renderer requested for the (asymmetric R/B) listening line.
    scan=bytearray();palette=set();greencount=0
    for y in range(544):
        o=start+3*960*(543-y);row=b[o:o+3*960];rgb=bytearray(len(row))
        rgb[::3],rgb[1::3],rgb[2::3]=row[2::3],row[1::3],row[::3]
        for x in range(0,len(row),3):
            pixel=tuple(rgb[x:x+3]);palette.add(pixel)
            if pixel==(120,255,163):assert 12<=y<26;greencount+=1
        scan.extend(bytes([0])+rgb)
    assert palette=={(12,12,12),(120,255,163),(204,204,204)} and greencount>0
    png=bytes.fromhex('89504e470d0a1a0a')+chunk(b'IHDR',struct.pack('>IIBBBBB',960,544,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan,9))+chunk(b'IEND',b'')
    if args.preview:
        args.preview.write_bytes(png)
        assert args.preview.read_bytes()==png
    print('PASS BMP readback / PNG 960x544, green pixels=',greencount,'PNG sha256=',hashlib.sha256(png).hexdigest())
