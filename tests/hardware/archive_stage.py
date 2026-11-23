"""Read-only archive-stage observations. Source files may predate this run; never treats it as the failing syscall."""
from pathlib import Path
import sys,json,hashlib,zipfile,tempfile,subprocess
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'tools'))
import r1ctl as r,s1_live as t
p=R.parent/'v1.33/build/workbench_0133.vpk';assert r.sha(p.read_bytes())=='9008ce18a1caa99a880687d49febe586abc4dc767f4bfd7cdf5cf4314958b1e3'
with zipfile.ZipFile(p) as z:members={n:z.read(n) for n in z.namelist()}
cid=r.parse_sfo(members['sce_sys/param.sfo']).get('CONTENT_ID','')
with tempfile.TemporaryDirectory() as temp:
 d=Path(temp);src=R/'source';f=d/'head.c';exe=d/'head.exe'
 # Work around Windows CRT text translation by comparing native head SHA instead of writing binary to stdout.
 f.write_text('#include "wb_head.h"\n#include "wb_sha256.h"\n#include <stdio.h>\nint main(int ac,char **v){unsigned char b[WB_HEAD_SIZE],h[32];wb_sha256 s;char o[65];if(ac!=2||wb_head_build(b,sizeof b,"INAP00018",v[1]))return 2;wb_sha256_init(&s);wb_sha256_update(&s,b,sizeof b);wb_sha256_final(&s,h);wb_sha_hex(h,32,o);printf("%u %s",(unsigned)sizeof b,o);return 0;}')
 subprocess.run(['gcc','-I'+str(src),str(f),*[str(src/(n+'.c')) for n in ['wb_head','wb_sha1','wb_sha256']],'-o',str(exe)],check=True);size,sha=subprocess.check_output([str(exe),cid],text=True).split()
 exp={n:(len(b),r.sha(b)) for n,b in members.items()};exp['sce_sys/package/head.bin']=(int(size),sha)
ev=[];result={}
with r.Session(ev) as s:
 snap=r.sample(s);assert snap['build']==t.OLD and t.issue(s,'pending')==(0,'pending-core: no')
 # A new authenticated read-only exec per member for old libssh; never replay a write.
for n,(size,h) in exp.items():
  assert r.local_trust()==(snap['host_pin'],snap['pin_file_sha256'])
  cmd='inspect ux0:data/INAP00018/stage/pkg/'+n
  rc,out=t.w.ssh(cmd,timeout=15);ev.append(dict(command=cmd,rc=rc,output=out));print(n,rc,out[:92],flush=True)
  result[n]={'matches':f'file bytes={size} sha256={h}' in out.splitlines(),'expected_sha256':h,'expected_bytes':size,'rc':rc}
r.save(t.D/'previous-stage.json',dict(utc=r.utc(),observed=snap,members=result,events=ev));print(result)
