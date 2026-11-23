"""Run production updater code with OS fakes; all fixture paths are disposable."""
import hashlib,json,pathlib,subprocess,sys,tempfile,zipfile,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
R=HERE.parents[1]
S=R/'source'
current=re.search(r'^#define\s+WB_VERSION\s+"([0-9.]+)"',(S/'wb_ver.h').read_text(),re.M)[1]; a,b=current.split('.');n=int(a)*100+int(b)+1;target=f'{n//100:02d}.{n%100:02d}';assert len(target)==len(current)==5, 'version rollover keeps the fixed width'
pkg=R.parent/'v1.32/build/workbench_0132.vpk'  # RC is nested under v1.77; same digest-pinned fixture.
assert hashlib.sha256(pkg.read_bytes()).hexdigest()=='7692e0b5c3dc949cecfb386e6cc53542eb5071903873f10d2627ca8b2dac702c'
with zipfile.ZipFile(pkg) as z:sfo=z.read('sce_sys/param.sfo')
assert sfo.count(b'01.32\0')==1
modes=['approved','no-consent','expired','other-source','other-receipt','stale-stage','native-error',
       'rtc-error','proof-rename-error','relaunch-error','truncated','intent-unlink-error','selfcheck','post-measure-receipt-rewrite']
records=[]
with tempfile.TemporaryDirectory(prefix='wb-r1-updater-') as t:
 p=Path(t);exe=p/'test.exe';units='wb_install wb_vita_io wb_zip wb_head wb_path wb_str wb_crc32 wb_err wb_sfo wb_inflate wb_sha256 wb_sha1'.split()
 cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Os','-DTEST_TARGET="'+target+'"','-I'+str(S),'-idirafter',str(R/'tests/stub'),str(HERE/'host.c'),*[str(S/(u+'.c')) for u in units],'-o',str(exe)]
 subprocess.run(cmd,cwd=t,check=True)
 for mode in modes:
  d=p/mode;stage=d/'ux0_data/INAP00018/stage/pkg';(stage/'sce_sys/package').mkdir(parents=True)
  (d/'ux0_data/INAP00019').mkdir();inst=d/'ux0_app/INAP00018/sce_sys';inst.mkdir(parents=True)
  (stage/'sce_sys/param.sfo').write_bytes(sfo.replace(b'01.32\0',(target+'\0').encode()))
  (inst/'param.sfo').write_bytes(sfo.replace(b'01.32\0',(current+'\0').encode()))
  for f in ('eboot.bin','sce_sys/package/head.bin','workbench_payload.suprx'):(stage/f).write_bytes(b'inert, not executable')
  a=subprocess.run([str(exe),mode],cwd=d,capture_output=True,text=True)
  print(a.stdout,a.stderr,sep='',end='');records.append(dict(mode=mode,cmd=a.args,rc=a.returncode,stdout=a.stdout,stderr=a.stderr))
  if a.returncode:sys.exit(a.returncode or 1)
out=R/'evidence/host-r1-updater.json'
out.write_text(json.dumps(dict(scope='native host fixture, real updater main; no Vita',compile=cmd,count=len(records),cases=records),indent=2)+'\n',encoding='utf8')
print(f'{len(records)}/{len(modes)} updater cases passed (host only)')
