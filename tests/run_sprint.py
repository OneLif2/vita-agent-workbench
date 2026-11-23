"""5090 positive and negative host gate. No network, never controls the Vita."""
import datetime, hashlib, json, subprocess, sys
from pathlib import Path
r=Path(__file__).resolve().parents[1]
py=sys.executable
tests=[
 ('S1','tests/s1/run.py'),('S2,S3','tests/transport_hash/run.py','--baseline',str(r.parent/'v1.31')),
 ('S4,C2','tests/job_arm_timeline/run.py'),('M3-client','tests/space/test_space.py'),('M3-core','tests/space/native.py'),
 ('registry-C','tests/device_registry/run.py'),('registry-build','tests/registry_table/test_table.py'),
 ('job-verdict','tests/job_verdict/test_verdict.py'),('pinned-in-place','tests/in_place/test_check.py'),
 ('ssh-pin','tests/pairing/test_pinned.py'),('dispatch','tests/dispatch/run.py','source/vita_ssh_status.c')]
ev=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),events=[])
for name,*args in tests:
 cmd=[py,'-B',*args];x=subprocess.run(cmd,cwd=r,capture_output=True,text=True,encoding='utf8',errors='replace')
 ev['events'].append(dict(suite=name,cmd=cmd,rc=x.returncode,stdout=x.stdout,stderr=x.stderr))
 print(name,x.returncode,(x.stdout or x.stderr)[-360:],flush=True)
out=r/'evidence/host-suites.json';out.write_text(json.dumps(ev,indent=2)+'\n',encoding='utf8')
sys.exit(int(any(t['rc'] for t in ev['events'])))
