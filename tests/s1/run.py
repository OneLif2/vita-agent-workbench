"""Host-only: real install/queue and updater gate, OS filesystem adapter. Never connects to a device."""
import hashlib,json,pathlib,shutil,subprocess,sys,tempfile,zipfile
p=pathlib.Path(__file__).resolve();r=p.parents[2];s=r/'source'
pkg=r.parent/'v1.31/build/workbench_0131.vpk'  # RC is nested under v1.77; same digest-pinned fixture.
h=lambda b:hashlib.sha256(b).hexdigest()
assert h(pkg.read_bytes())=='39bf12797bb1a7c4de78c67ea99aacec3729e69f1db7783579b991c86f1fed20'
units=['wb_install.c','wb_vita_io.c','wb_zip.c','wb_head.c','wb_path.c','wb_str.c','wb_crc32.c','wb_err.c','wb_sfo.c','wb_inflate.c','wb_sha256.c','wb_sha1.c']
with tempfile.TemporaryDirectory(prefix='wbq2-host-') as t:
 d=pathlib.Path(t);x=d/'s1host.exe';(d/'ux0_data/INAP00019').mkdir(parents=True);(d/'ux0_data/INAP00018/stage').mkdir(parents=True);sf=d/'ux0_app/INAP00018/sce_sys/param.sfo';sf.parent.mkdir(parents=True)
 with zipfile.ZipFile(pkg) as z:sf.write_bytes(z.read('sce_sys/param.sfo'))
 shutil.copyfile(pkg,d/'core.vpk')
 cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Os','-I'+str(s),'-idirafter',str(r/'tests/stub'),str(p.parent/'host.c'),*[str(s/u) for u in units],'-o',str(x)]
 records=[]
 for c in (cmd,[str(x),h(pkg.read_bytes())]):
  cp=subprocess.run(c,cwd=d,text=True,capture_output=True);records.append(dict(cmd=c,rc=cp.returncode,out=cp.stdout,err=cp.stderr))
  print(cp.stdout,cp.stderr,sep='',end='')
  if cp.returncode:sys.exit(cp.returncode)
 ev=r/'evidence/host-s1.json';ev.write_text(json.dumps(records,indent=2)+'\n',encoding='utf8')

