"""Offline R1 gate; none of these suites may connect to the paired console."""
import datetime, hashlib, json, os, subprocess, sys
from pathlib import Path
r=Path(__file__).resolve().parents[1]
suites={'r1-policy':['tests/return_policy/run.py','--out','evidence/host-return-policy.json'],
        'r1-updater':['tests/return_updater/run.py'],
        'r1-core':['tests/return_core/run.py'],
        'r1-5090':['tests/return_5090/test_r1ctl.py'],
        'inherited-11-suites':['tests/run_sprint.py']}
report={'scope':'5090 host, native I/O fixtures and loopback; no Vita','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'events':[]}
for name,args in suites.items():
    cmd=[sys.executable,'-B',*args]
    p=subprocess.run(cmd,cwd=r,capture_output=True,encoding='utf8',errors='replace',env={**os.environ,'PYTHONIOENCODING':'utf-8'})
    report['events'].append(dict(name=name,argv=cmd,rc=p.returncode,stdout=p.stdout,stderr=p.stderr))
    print(name,p.returncode,(p.stdout or p.stderr)[-260:],flush=True)
report['passed']=all(x['rc']==0 for x in report['events'])
(r/'evidence/HOST.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
sys.exit(0 if report['passed'] else 1)

