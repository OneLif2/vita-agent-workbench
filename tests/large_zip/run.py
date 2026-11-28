"""Host-only ZIP32 bounded-memory tests. Generates real large entries in temp storage.
No network/device access; no stopped timing or acceptance workflow is invoked.
"""
import ctypes, datetime, hashlib, io, json, pathlib, random, re, struct, subprocess, sys, tempfile, zipfile, zlib
r=pathlib.Path(__file__).resolve().parents[2];s=r/'source'; evidence=r/'evidence/large-zip.json'
records=[]
def run(cmd):
 p=subprocess.run([str(x) for x in cmd],text=True,capture_output=True)
 rec=dict(cmd=[str(x) for x in cmd],rc=p.returncode,stdout=p.stdout,stderr=p.stderr);records.append(rec)
 print(p.stdout,p.stderr,sep='',end='',flush=True)
 if p.returncode:raise RuntimeError(rec)
 return p.stdout

def patch(data,where,offset,value,fmt='<I'):
 b=bytearray(data); pos=b.index(where);struct.pack_into(fmt,b,pos+offset,value);return bytes(b)
def fixture(path,name='ok.bin',data=b'valid-content'*200,method=zipfile.ZIP_DEFLATED):
 with zipfile.ZipFile(path,'w',compression=method) as z:z.writestr(name,data)
 return path.read_bytes()

try:
 with tempfile.TemporaryDirectory(prefix='wb209-zip-') as temp:
  t=pathlib.Path(temp);exe=t/'zip.exe';objects=[]
  for unit in ('wb_zip.c','wb_inflate.c','wb_crc32.c'):
   obj=t/(unit+'.o');objects.append(obj)
   run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-Dmalloc=test_malloc','-Dcalloc=test_calloc','-Dfree=test_free','-I'+str(s),'-c',s/unit,'-o',obj])
  run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(s),r/'tests/large_zip/host.c',*objects,'-o',exe])
  def check(path,rc=0,fail=0,readfail=0,bounded=True):
   out=run([exe,path,rc,fail,readfail]); vals=dict((k,int(v)) for k,v in re.findall(r'(\w+)=(-?\d+)',out))
   if bounded:assert vals['peak_alloc']<140000,vals
   if rc==0:assert vals['max_write']<=16384 and vals['max_read']<=16384,vals
   return vals
  # Differential oracle: standard-library zlib generates dynamic/fixed/Huffman/
  # RLE/stored streams; the independent existing decoder must reproduce bytes.
  dll=t/'inflate.dll'
  run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-shared','-I'+str(s),s/'wb_inflate.c','-o',dll])
  lib=ctypes.CDLL(str(dll));fn=lib.wb_inflate_raw
  fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
  rng=random.Random(209)
  for i in range(250):
   n=rng.randrange(120000)
   data=(rng.randbytes(n) if i%3==0 else (b'ABCD'+rng.randbytes(i%31+1))*(n//(i%31+5)+1))[:n]
   strategy=(zlib.Z_DEFAULT_STRATEGY,zlib.Z_FIXED,zlib.Z_HUFFMAN_ONLY,zlib.Z_RLE)[i%4]
   c=zlib.compressobj(0 if i%9==0 else i%9,wbits=-15,strategy=strategy);raw=c.compress(data)+c.flush()
   out=ctypes.create_string_buffer(max(n,1));count=ctypes.c_size_t()
   rc=fn(out,n,ctypes.byref(count),raw,len(raw))
   assert rc==0 and count.value==n and out.raw[:n]==data,(i,rc,count.value,n)
   # Valid stream plus one extraneous compressed byte is never accepted.
   assert fn(out,n,ctypes.byref(count),raw+b'X',len(raw)+1)==-3
  # A bounded malformed corpus exercises Huffman construction / short inputs.
  for i in range(2000):
   raw=rng.randbytes(rng.randrange(1,96));out=ctypes.create_string_buffer(4096);count=ctypes.c_size_t()
   rc=fn(out,4096,ctypes.byref(count),raw,len(raw))
   assert rc in (0,-3,-5,-17) and count.value<=4096,(i,rc,count.value)
  # Windows holds loaded DLLs open; unload before TemporaryDirectory cleanup.
  import _ctypes
  if sys.platform=='win32':_ctypes.FreeLibrary(lib._handle)
  else:_ctypes.dlclose(lib._handle)
  del fn,lib
  records.append(dict(test='raw DEFLATE differential',streams=250,trailing_rejections=250,malformed_streams=2000,rc=0))
  print('raw DEFLATE differential:250 streams +250 trailing-byte rejections PASS',flush=True)
  p=t/'small.zip';base=fixture(p);check(p)
  # Bit-3 descriptors, including signature-free descriptors, preserve metadata
  # consistency checks while allowing streaming ZIP producers.
  mem=io.BytesIO()
  class Unseekable:
   def write(self,b):return mem.write(b)
   def flush(self):pass
  with zipfile.ZipFile(Unseekable(),'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('descriptor.bin',b'descriptor'*10000)
  descriptor=mem.getvalue();p=t/'descriptor.zip';p.write_bytes(descriptor);check(p)
  b=bytearray(descriptor);desc=b.index(b'PK\x07\x08');struct.pack_into('<I',b,desc+4,123)
  p=t/'bad-descriptor.zip';p.write_bytes(b);check(p,-3)
  # Remove optional descriptor signature and adjust EOCD central offset.
  b=bytearray(descriptor);del b[desc:desc+4];eo=b.index(b'PK\x05\x06');struct.pack_into('<I',b,eo+16,struct.unpack_from('<I',b,eo+16)[0]-4)
  p=t/'unsigned-descriptor.zip';p.write_bytes(b);check(p)
  # Small ZIP64 encoded local headers are unsupported, not a RAM size failure.
  mem=io.BytesIO()
  with zipfile.ZipFile(mem,'w') as z:
   with z.open('zip64-small.bin','w',force_zip64=True) as f:f.write(b'zip64')
  p=t/'zip64-local.zip';p.write_bytes(mem.getvalue());check(p,-18)
  p=t/'expanded-320MiB.zip'
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=False) as z:
   for name in ('large-a.bin','large-b.bin'):
    with z.open(name,'w') as f:
     for _ in range(160):f.write(b'ABCD'*(1024*1024//4))
  # Same generated real 320MiB input against untouched parent engine.
  parent=r.parent/'v2.08/source';old_objects=[]
  for unit in ('wb_zip.c','wb_inflate.c','wb_crc32.c'):
   obj=t/('parent-'+unit+'.o');old_objects.append(obj)
   run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-Dmalloc=test_malloc','-Dcalloc=test_calloc','-Dfree=test_free','-I'+str(parent),'-c',parent/unit,'-o',obj])
  old_exe=t/'parent-zip.exe'
  run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(parent),r/'tests/large_zip/host.c',*old_objects,'-o',old_exe])
  run([old_exe,p,-5]);records[-1]['role']='BASELINE untouched v2.08 same320MiB input'
  v=check(p);assert v['bytes']==320*1024*1024
  records[-1]['fixture']=dict(compressed_bytes=p.stat().st_size,expanded_bytes=v['bytes'],sha256=hashlib.sha256(p.read_bytes()).hexdigest())
  p=t/'incompressible-40MiB.zip';rng=random.Random(209)
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=False) as z:
   with z.open('random.bin','w') as f:
    for _ in range(40):f.write(rng.randbytes(1024*1024))
  assert p.stat().st_size>33*1024*1024
  v=check(p);assert v['bytes']==40*1024*1024
  records[-1]['fixture']=dict(compressed_bytes=p.stat().st_size,expanded_bytes=v['bytes'],sha256=hashlib.sha256(p.read_bytes()).hexdigest())
  p=t/'stored-40MiB.zip'
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_STORED,allowZip64=False) as z:
   with z.open('stored.bin','w') as f:
    for _ in range(40):f.write(bytes(1024*1024))
  check(p)
  p=t/'many.zip'
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_STORED,allowZip64=False) as z:
   for n in range(4097):z.writestr(f'f{n:05}.bin',b'')
  v=check(p,bounded=False);assert v['files']==4097
  # A uint64 metadata sum beyond 4GiB must pass preflight; intentionally stop
  # at create before expanding malicious size declarations (not success data).
  p=t/'sum-64bit.zip'
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_STORED) as z:
   z.writestr('first.bin',b'');z.writestr('second.bin',b'')
  b=bytearray(p.read_bytes());pos=0
  for sig,sizeoff in ((b'PK\x03\x04',22),(b'PK\x01\x02',24)):
   pos=0
   for _ in range(2):
    pos=b.index(sig,pos);struct.pack_into('<I',b,pos+sizeoff,0xfffffffe);pos+=4
  p.write_bytes(b);v=check(p,-2,2);assert v['creates']==1
  negatives={
   'path-traversal.zip':(lambda:fixture(t/'x.zip','../escape'),-13),
   'local-name.zip':(lambda:base[:30]+b'X'+base[31:],-3),
   'local-method.zip':(lambda:patch(base,b'PK\x03\x04',8,0,'<H'),-3),
   'encrypted.zip':(lambda:patch(base,b'PK\x01\x02',8,1,'<H'),-4),
   'symlink.zip':(lambda:patch(base,b'PK\x01\x02',38,0o120777<<16),-4),
   'device.zip':(lambda:patch(base,b'PK\x01\x02',38,0o020600<<16),-4),
   'zip64-size.zip':(lambda:patch(base,b'PK\x01\x02',24,0xffffffff),-18),
   'zip64-offset.zip':(lambda:patch(base,b'PK\x01\x02',42,0xffffffff),-18),
   'zip64-count.zip':(lambda:patch(patch(base,b'PK\x05\x06',8,0xffff,'<H'),b'PK\x05\x06',10,0xffff,'<H'),-18),
   'truncated.zip':(lambda:base[:-1],-3),
  }
  for name,(fn,rc) in negatives.items():
   p=t/name;p.write_bytes(fn());check(p,rc)
  p=t/'duplicates.zip'
  with zipfile.ZipFile(p,'w') as z:z.writestr('File.bin',b'a');z.writestr('file.bin',b'b')
  check(p,-3)
  p=t/'crc.zip';b=patch(base,b'PK\x01\x02',16,123);b=patch(b,b'PK\x03\x04',14,123);p.write_bytes(b)
  v=check(p,-3);assert v['closes']==1 and v['files']==0
  p=t/'small.zip';p.write_bytes(base)
  for fail in (1,2,3):
   v=check(p,-2,fail);assert v['closes']==(0 if fail==2 else 1)
  # Truncated DEFLATE data with otherwise self-consistent archive bounds.
  c=base.index(b'PK\x01\x02');n=struct.unpack_from('<I',base,c+20)[0]
  p=t/'broken-deflate.zip';b=bytearray(base);b[30+len('ok.bin')]=0xff;p.write_bytes(b);check(p,-3)
  # The precise input callback error is preserved, including closing the file.
  p=t/'read-error.zip';fixture(p,data=b'x'*100000,method=zipfile.ZIP_STORED)
  v=check(p,-2,readfail=1);assert v['closes']==1 and v['creates']==1
finally:
 evidence.parent.mkdir(exist_ok=True)
 evidence.write_text(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='HOST-ONLY; no Vita / promotion',records=records),indent=2)+'\n',encoding='utf8')
print('large ZIP32 streaming / malicious inputs / sink failures PASS')
