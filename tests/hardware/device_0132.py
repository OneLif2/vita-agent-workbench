"""Physical acceptance phases. Bootstrap is one-shot; poll/core-check never reinstall.
Run from 5090 using only the owner's already paired host. No destructive fault injection."""
import argparse, datetime, hashlib, json, os, re, sys, time
from pathlib import Path
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'tools'))
import wbctl as w, pinned_check as pc, space_budget as space
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def require(ok,msg):
 if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def save(n,data):
 with (d/n).open('x',encoding='utf8') as f:json.dump(data,f,indent=2);f.write('\n')
def note(**data):
 with (d/'wire.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(dict(utc=now(),**data))+'\n')
def pin():
 fp=json.loads((R/'evidence/physical-owner.json').read_text())['host_fingerprint']
 require((w.HOST,int(w.PORT),w.USER)==('192.0.2.10',2222,'pi') and pc.canonical_saved(pc.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))[1]==fp,'endpoint/pin changed');return fp
def call(cmd,data=None,t=14):
 pin();rc,out=w.ssh(cmd,stdin_bytes=data,timeout=t);note(cmd=cmd,rc=rc,output=out);print(rc,cmd,out[:470],flush=True)
 require(rc!=78,'SSH trust failure; STOP');return rc,out
def ok(cmd,data=None,t=14):
 rc,out=call(cmd,data,t);require(rc==0 and not any(x.startswith('ERR ') for x in out.splitlines()),cmd+' failed');return out
def after():
 out=ok('ver');r=re.fullmatch(r'wb version=01\.32 build=01\.32-live-wbq2 abi=3 proto=wb10 run=([A-F0-9]{16}) payload=\S+ uptime_ms=\d+',out)
 require(r,'not target version');return r[1]
def bootstrap():
 require(not (d/'intent.json').exists(),'do not resend bootstrap; inspect last receipt')
 gate=json.loads((R/'evidence/HOST.json').read_text());require(gate['result']=='PASS','host gate not passed')
 p=R/'build/workbench_0132.vpk';raw=p.read_bytes();h=sha(raw);local=json.loads((R/'build/RELEASE-INPUTS.json').read_text())
 require(h==local['sha256'] and gate['core_vpk_sha256']==h,'not the host-tested VPK')
 old=ok('ver');m=re.search(r'version=01\.31 build=01\.31-live-registry1 .*?run=([A-F0-9]{16})',old)
 require(m,'baseline is not 01.31; do not upload');require(ok('pending')=='pending-core: no','existing queued update')
 remote=f'ux0:/VITA-POC/wb0132-{h[:10]}-{os.urandom(3).hex()}.vpk'
 save('intent.json',dict(utc=now(),old_run=m[1],pin=pin(),sha256=h,remote=remote))
 resp=ok(f'put {remote} {len(raw)} sha256={h}',raw,140);require(f'OK put path={remote} bytes={len(raw)} sha256={h}' in resp.splitlines(),'upload mismatch')
 resp=ok('inspect '+remote,t=45);require('title_id=INAP00018 app_ver=01.32 ' in resp and f'file bytes={len(raw)} sha256={h}' in resp,'wrong file')
 resp=ok(f'install {remote} sha256={h}',t=100);require('OK install version=01.32 title=INAP00018 ' in resp and 'core=queued' in resp,'not queued')
 require(ok('pending')=='pending-core: WBQ1 01.32','unexpected old-core queue')
 note(apply_issued=True,do_not_resend=True);rc,out=call('apply-core',t=40)
 require(rc in (0,124,255) and 'ERR ' not in out,'apply failed')
def poll():
 old=json.loads((d/'intent.json').read_text())['old_run'];deadline=time.monotonic()+a.timeout
 while time.monotonic()<deadline:
  rc,o=call('ver',t=7)
  if rc==0 and 'version=01.32 build=01.32-live-wbq2' in o:
   run=after();require(run!=old and ok('pending')=='pending-core: no','incomplete boot')
   st=ok('status');require('run='+run in st,'state changed during boot check')
   save('boot.json',dict(utc=now(),run=run,prior=old,status=st,pin=pin(),timeline=ok('timeline'),note='old updater bootstrap; NOT S1 acceptance'));return
  time.sleep(4)
 raise ValueError('not listening on paired endpoint yet; poll only')
def storage():
 run=after();src=R/'build/workbench_0132.vpk';facts=w.vpk_facts(src)
 before=ok('df');m=re.fullmatch('df volume=ux0: total=(\\d+) available=(\\d+) required=0',before)
 require(m,'no real capacity');total,avail=map(int,m.groups());need=space.requirement(facts)['required'];require(0<need<=avail<=total,'insufficient for positive case')
 yes=ok(f'df {need}');require(f'required={need}' in yes,'positive missing')
 # Call the actual public CLI implementation with a real capacity and a configurable
 # free-space reserve equal to total capacity. Never allocate or fill the Vita.
 # Guard against a buggy client: do not transmit even a single mutating request.
 transport=w.ssh;calls=[]
 def watch(cmd,**kw):
  calls.append(cmd)
  require(cmd=='ver' or cmd.startswith('df '),'unexpected write after negative budget')
  rc,out=transport(cmd,**kw);note(phase='actual wbctl.update',cmd=cmd,rc=rc,output=out);return rc,out
 import contextlib,io
 buf=io.StringIO()
 try:
  w.ssh=watch
  with contextlib.redirect_stdout(buf):code=w.main(['update',str(src),'--force','--yes','--reserve-bytes',str(total)])
 finally:w.ssh=transport
 require(code==8 and 'space-preflight-insufficient' in buf.getvalue() and len(calls)==2,'negative client failed')
 plan=space.probe(lambda cmd:call(cmd),need)
 require(plan['ok'] and after()==run and ok('pending')=='pending-core: no','state drift')
 save('M3.json',dict(result='PASS',utc=now(),total=total,available=avail,positive=yes,negative_cli_rc=code,negative_cli_output=buf.getvalue(),calls=calls,run=run))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('phase',choices=['bootstrap','poll','storage']);ap.add_argument('--dir',type=Path,required=True);ap.add_argument('--timeout',type=int,default=75);a=ap.parse_args();d=a.dir.resolve();d.mkdir(parents=True,exist_ok=True)
 try: {'bootstrap':bootstrap,'poll':poll,'storage':storage}[a.phase]()
 except (OSError,ValueError,RuntimeError,KeyError) as e:print('STOP:',e,file=sys.stderr);sys.exit(2)
