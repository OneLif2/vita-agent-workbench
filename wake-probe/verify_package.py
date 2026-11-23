"""Read-only exact four-member 01.02 dual-safe-userland package verifier. No device I/O."""
from pathlib import Path
import struct,zipfile,io,zlib,hashlib,json,sys
h=lambda b:hashlib.sha256(b).hexdigest()
def sfo(b):
 assert b[:4]==b'\0PSF';_,ko,vo,n=struct.unpack_from('<IIII',b,4);out={}
 for i in range(n):
  k,fmt,length,cap,st=struct.unpack_from('<HHIII',b,20+i*16);key=b[ko+k:b.index(0,ko+k)].decode();assert key not in out and length<=cap and vo+st+length<=len(b);v=b[vo+st:vo+st+length];out[key]=struct.unpack('<I',v)[0] if fmt==0x404 else v.rstrip(b'\0').decode() if fmt==0x204 else v.hex()
 return out
def self_info(b,attr,budget):
 assert b[:4]==b'SCE\0' and len(b)==struct.unpack_from('<Q',b,0x20)[0]
 info,e=struct.unpack_from('<QQ',b,0x38);assert struct.unpack_from('<Q',b,info)[0]==0x2f00000000000002
 assert b[e:e+7]==b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H',b,e+18)[0]==40
 off,size=struct.unpack_from('<QQ',b,0x68);end=off+size;assert end<=len(b);c6=[]
 while off<end:
  kind,n=struct.unpack_from('<II',b,off);assert n>=16 and off+n<=end
  if kind==6:c6.append(struct.unpack_from('<IIII',b,off+16))
  off+=n
 assert c6==[(1,attr,0,budget)]
 ei,ph,_,si=struct.unpack_from('<QQQQ',b,0x40);ep=struct.unpack_from('<I',b,ei+24)[0];idx=ep>>30;entry=ep&((1<<30)-1)
 ptype,po,pva,pa,pfiles,pmem,flags,align=struct.unpack_from('<IIIIIIII',b,ph+32*idx);offset,length,comp,enc=struct.unpack_from('<QQQQ',b,si+32*idx);assert ptype==1 and enc==2 and offset+length<=len(b) and comp in (1,2)
 seg=b[offset:offset+length];seg=zlib.decompress(seg) if comp==2 else seg;assert len(seg)==pfiles;pos,last=struct.unpack_from('<II',seg,entry+0x2c);assert pos<last<=len(seg);imports={}
 while pos<last:
  sz,v,f,n=struct.unpack_from('<4H',seg,pos);assert sz==52 and pos+sz<=last;_,name=struct.unpack_from('<II',seg,pos+16);name-=pva;assert 0<=name<len(seg);name=seg[name:seg.index(0,name)].decode();assert name not in imports;imports[name]=f;pos+=sz
 assert pos==last and not any(k.startswith(('SceNet','SceShell','SceCtrl','SceDisplay','SceGxm','ScePromoter')) for k in imports)
 return {'authid':'0x2f00000000000002','attr':attr,'memory_kib':budget,'imports':imports,'sha256':h(b)}
def verify(p):
 raw=Path(p).read_bytes()
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  assert len(z.infolist())==4 and sorted(z.namelist())==['eboot.bin','eboot2.bin','sce_sys/param.sfo','sce_sys/param2.sfo'] and z.testzip() is None
  fg=sfo(z.read('sce_sys/param.sfo'));bg=sfo(z.read('sce_sys/param2.sfo'))
  assert (fg['TITLE_ID'],fg['TITLE'],fg['CATEGORY'],fg['ATTRIBUTE'],fg['PUBTOOLINFO'],fg['APP_VER'])==('WBLC00079','WB Lifecycle','gdc',16809984,'has_bg=1','01.02')
  assert (bg['TITLE_ID'],bg['TITLE'],bg['CATEGORY'],bg['ATTRIBUTE'],bg['INSTALL_DIR_SAVEDATA'],bg['INSTALL_DIR_ADDCONT'],bg['APP_VER'])==('WBLB00079','WB Lifecycle BG','gdd',17305600,'WBLC00079','WBLC00079','01.02')
  a=self_info(z.read('eboot.bin'),0,8192);b=self_info(z.read('eboot2.bin'),3,4096)
  assert a['imports'].get('SceBgAppUtil')==8 and 'SceBgAppUtil' not in b['imports'] and not any(k.startswith('SceAppMgr') for k in b['imports'])
  members={i.filename:{'bytes':i.file_size,'sha256':h(z.read(i.filename))} for i in z.infolist()}
 return {'passed':True,'scope':'Offline package only; not installation, scheduling, return or WAKE proof','title':'WBLC00079','version':'01.02','bytes':len(raw),'sha256':h(raw),'foreground':a,'background':b,'members':members}
if __name__=='__main__':print(json.dumps(verify(sys.argv[1]),indent=2))
