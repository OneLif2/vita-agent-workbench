"""Actual headless foreground/worker C with local Vita API stubs. Never Vita/Jetson."""
from pathlib import Path
import subprocess,tempfile,shutil,json,hashlib,datetime,sys
D=Path(__file__).resolve().parents[1];S=D/'sources';T=D/'tests';OUT=D/'evidence/HOST-TESTS.json';OUT.parent.mkdir(exist_ok=True)
rows=[]
def run(label,argv,cwd):
 p=subprocess.run([str(x) for x in argv],cwd=cwd,capture_output=True,text=True,timeout=30)
 r=dict(label=label,argv=[str(x) for x in argv],exit=p.returncode,stdout=p.stdout,stderr=p.stderr);rows.append(r)
 if p.returncode:raise AssertionError(r)
 return p.stdout
history=[]
if OUT.exists():history=json.loads(OUT.read_text()).get('historical_runs',[])+[json.loads(OUT.read_text())|{'historical_runs':[]}]
report=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='SDK stubs only; actual main/worker/storage/probe_io C. No Vita/Jetson; no AppMgr scheduling claim.',commands=rows,passed=False,historical_runs=history)
try:
 with tempfile.TemporaryDirectory(prefix='wp-native-') as td:
  p=Path(td);inc=p/'include'
  for n in ['apputil','io/fcntl','bgapputil','sysmodule','appmgr','rtc','kernel/processmgr','kernel/threadmgr']:
   h=inc/'psp2'/(n+'.h');h.parent.mkdir(parents=True,exist_ok=True);h.write_text('#include "fake.h"\n')
  cc=shutil.which('gcc');assert cc;flags=['-std=c11','-O1','-Wall','-Wextra','-Werror','-I'+str(inc),'-I'+str(T),'-I'+str(S),'-I'+str(D)]
  run('compile protocol',[cc,*flags,T/'protocol.c','-o',p/'protocol.exe'],p)
  print(run('protocol boundaries',[p/'protocol.exe'],p).strip())
  for name,symbol in [('main','probe_main'),('worker','worker_main')]:run('compile '+name,[cc,*flags,'-Dmain='+symbol,'-c',S/(name+'.c'),'-o',p/(name+'.o')],p)
  exe=p/'native.exe';run('link actual native paths',[cc,*flags,T/'native.c',S/'storage.c',S/'probe_io.c',p/'main.o',p/'worker.o','-o',exe],p)
  cases=['job-present-no-triangle','missing','short','trailing','badnonce','badid','expired','future','overttl','boot','clockrc','underflow','init','active','replay','claimsave','publicfail','syncfail','consume','modfail','bgfail','returnfail','mutate','workerjobchange','workerepoch','workerarm','workerrevoke','workertracefail','workerpublic','workergap','receiptwait','receipttorn','receipttimeout','slowmodule']
  for case in cases:print(run(case,[exe,case],p).strip())
  report.update(passed=True,case_count=len(cases),source_files=[dict(path=str(x),bytes=x.stat().st_size,sha256=hashlib.sha256(x.read_bytes()).hexdigest()) for x in [D/'wake_probe_protocol.h',*(S/n for n in ['main.c','worker.c','storage.c','probe_io.c','probe_io.h','life.h']),T/'native.c']])
finally:
 OUT.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
