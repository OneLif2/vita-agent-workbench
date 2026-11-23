"""Read-only bounded wait for a *specific* pinned build after a human or native handoff."""
import argparse,json,time,sys,datetime
from pathlib import Path
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'tools'))
import r1ctl as r,s1_live as t
p=argparse.ArgumentParser();p.add_argument('build',choices=[t.TRACE,t.NEW]);p.add_argument('--seconds',type=int,default=150);a=p.parse_args();assert 1<=a.seconds<=480
until=time.monotonic()+a.seconds;key=r.get(t.D/'baseline-refused.json')['source']
while time.monotonic()<until:
 e=[];reason=''
 try:
  with r.Session(e) as s:
   rc,o=s.cmd('ver');v=r.VR.fullmatch(o);assert rc==0 and v
   reason=v[2]+' '+v[5]
   if s.fp!=key['host_pin'] or s.pinhash!=key['pin_file_sha256']:raise r.Stop('TRUST_ERROR','identity drift')
   if v[2]==a.build and v[5]!=key['run']:
    t.line(t.D,'waits.jsonl',result='MATCH',events=e);print('MATCH',reason,flush=True);sys.exit(0)
 except r.Stop as x:
  reason=x.code+' '+str(x)
  if x.code=='TRUST_ERROR':t.line(t.D,'waits.jsonl',result=reason,events=e);sys.exit(3)
 except Exception as x:reason=type(x).__name__+': '+str(x)
 t.line(t.D,'waits.jsonl',result=reason,events=e);print(reason,flush=True);time.sleep(15)
sys.exit(2)
