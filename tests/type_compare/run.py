"""Native same-input A/B/rollback probe. Renders original C sources from a trusted local source directory or project snapshot."""
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
import argparse,hashlib,json,subprocess,tempfile,zipfile
H=Path(__file__).resolve().parent
def run(src,out):
 with tempfile.TemporaryDirectory() as td:
  t=Path(td);src=src.resolve()
  if src.is_file():
   with zipfile.ZipFile(src) as z:
    for n in z.namelist():
     p=Path(n)
     if p.parent.as_posix()=='source' and p.suffix in ('.h','.inc','.c'):
      (t/p.name).write_bytes(z.read(n))
   src=t
  api='wb_type_set(' in (src/'wb_panel_geometry.h').read_text()
  subprocess.run(['gcc','-O2','-std=c11','-DWB_CAN_STYLE='+str(int(api)),'-I'+str(src),str(H/'probe.c'),str(src/'wb_screen_mirror.c'),'-o',str(t/'p.exe')],check=True,capture_output=True)
  images=[];data=[]
  for mode in range(4):
   ppm=t/f'{mode}.ppm';tx=subprocess.run([str(t/'p.exe'),str(mode),str(ppm)],capture_output=True,check=True)
   im=Image.open(ppm).convert('RGB');body=im.crop((0,69,960,519));images.append(body.copy())
   # Find the bands occupied by the first H on four consecutive lines.
   runs=[];start=None
   for y in range(body.height):
    lit=any(body.getpixel((x,y))==(204,204,204) for x in range(9))
    if lit and start is None:start=y
    if not lit and start is not None:runs.append((start,y));start=None
   assert len(runs)==4,(mode,runs)
   pitch=runs[1][0]-runs[0][0];assert all(b[0]-a[0]==pitch for a,b in zip(runs,runs[1:]))
   data.append(dict(mode=mode,terminal=tx.stdout.decode().strip(),row_pitch_px=pitch,first_H_height=runs[0][1]-runs[0][0],body_sha256=hashlib.sha256(body.tobytes()).hexdigest()))
  assert data[0]['row_pitch_px']==20
  if api:
   assert [i['row_pitch_px'] for i in data]==[20,22,20,34] and data[0]['first_H_height']==data[1]['first_H_height']==14 and len({r['body_sha256'] for r in data})==4
  else:assert len({i['body_sha256'] for i in data})==1
  if out:
   labels=['classic  2x   gap x=2, y=6   |   12 x 20 px cell (default)','classic  2x   gap x=2, y=8   |   12 x 22 px cell (more space, same letters)','jetbrains  1x   gap x=2, y=6   |   10 x 20 px cell','jetbrains  2x   gap x=2, y=6   |   18 x 34 px cell']
   tile=Image.new('RGB',(640,548),'#111111');d=ImageDraw.Draw(tile);y=4
   for im,lab,hi in zip(images,labels,(84,92,84,140)):
    d.text((8,y),lab,fill='#80ffac');y+=22;tile.paste(im.crop((0,0,632,hi)),(8,y));y+=hi+6
   tile.crop((0,0,640,y)).save(out)
  print(json.dumps(data,separators=(',',':')))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source',nargs='?',type=Path,default=H.parents[1]/'source');p.add_argument('--preview',type=Path);a=p.parse_args();run(a.source,a.preview)
