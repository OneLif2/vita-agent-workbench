"""Owner-controlled one-update return. Observe/capture/collect never modify the Vita.
Submit only consumes an independently created physical grant; never falls back to apply-core."""
from __future__ import annotations
import argparse, contextlib, datetime, hashlib, hmac, io, json, os, re, socket, subprocess, sys, tempfile, time, zipfile
from pathlib import Path
import pinned_check as pin
from check_in_place import VR,ST
from wbctl import parse_sfo,positive_handoff
from self_segments import parse_self,SelfError
R=Path(__file__).resolve().parents[1]
HOST='192.0.2.10';PORT=2222;USER='pi';VERSION_RE=r'\d{2}\.\d{2}'
class Stop(Exception):
 def __init__(self,code,why):super().__init__(why);self.code=code
def need(ok,why,code='INCONCLUSIVE'):
 if not ok:raise Stop(code,why)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b):return hashlib.sha256(b).hexdigest()
def get(j):return json.loads(j.read_text(encoding='utf8'))
def save(p,j):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('x',encoding='utf8') as f:json.dump(j,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
def local_package(path,approved,build):
 need(re.fullmatch('[0-9a-f]{64}',approved) and 22<=path.stat().st_size<=4*1024**2,'invalid local package')
 blob=path.read_bytes();need(sha(blob)==approved,'not approved local VPK','REFUSED')
 names=['eboot.bin','sce_sys/param.sfo','workbench_payload.suprx']
 with zipfile.ZipFile(io.BytesIO(blob)) as z:
  need(sorted(names)==sorted(z.namelist()) and all(0<i.file_size<=8*1024**2 for i in z.infolist()),'unexpected core archive')
  files=[z.read(n) for n in names]
 sfo=parse_sfo(files[1]);v=sfo.get('APP_VER','')
 need(sfo.get('TITLE_ID')=='INAP00018' and re.fullmatch(VERSION_RE,v),'wrong local product')
 try:
  logical_core=parse_self(files[0],label='approved core',required_authid=0x2F00000000000001).logical_bytes
 except SelfError:
  raise Stop('REFUSED','invalid approved core SELF') from None
 need(re.fullmatch(re.escape(v)+r'-[A-Za-z0-9._-]{1,40}',build) and build.encode()+b'\0' in logical_core,'wrong target build tag')
 with tempfile.TemporaryDirectory() as t:
  d=Path(t);c=R/'source';exe=d/('wbmanifest.exe' if os.name=='nt' else 'wbmanifest')
  subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(c),str(R/'tools/r1_manifest.c'),*[str(c/(n+'.c')) for n in ('wb_sfo','wb_sha256','wb_head','wb_sha1')],'-o',str(exe)],capture_output=True,check=True)
  fs=[]
  for i,content in enumerate(files):
   f=d/str(i);f.write_bytes(content);fs.append(str(f))
  receipt=subprocess.run([str(exe),*fs],capture_output=True,text=True,check=True).stdout.rstrip('\n')
 m=re.fullmatch('WBQ2 '+re.escape(v)+r' ([0-9a-f]{64}) ([1-9]\d*)',receipt);need(m,'invalid local receipt')
 return dict(version=v,build=build,manifest=m[1],receipt=receipt,vpk_sha256=approved)
def local_trust():
 exp=get(R/'evidence/physical-owner.json')['host_fingerprint']
 p,fp=pin.canonical_saved(pin.pin_path(HOST,PORT),HOST,PORT)
 need(fp==exp,'unrecognized saved owner pin','TRUST_ERROR');return fp,sha(p.read_bytes())
class Session:
 """R1 grant checks and readback share one paired PTY, not per-command SSH exec."""
 def __init__(self,journal): self.log=journal
 def __enter__(self):
  import wbterm
  self.fp,self.pinhash=local_trust()
  self.cm=wbterm.paired_terminal();self.term=self.cm.__enter__()
  try:
   need(self.term.host_pin==self.fp and local_trust()==(self.fp,self.pinhash),'owner pin changed','TRUST_ERROR')
   self.sid=self.term.transport_id
   self.log.append(dict(utc=utc(),kind='interactive-pty',transport_sha256=self.sid,host_sha256=self.fp))
   return self
  except BaseException:
   self.cm.__exit__(*sys.exc_info());raise
 def __exit__(self,*e):return self.cm.__exit__(*e)
 def cmd(self,cmd):
  need(cmd in ('ver','status','r1-status','pending') or re.fullmatch(r'apply-return [0-9A-F]{32}',cmd),'not an allowed command')
  from wbterm import ROOT_PROMPT
  self.term.command(cmd)
  # Only trusted core verbs with bounded, native outputs reach this method.
  # A stored WBQ2 receipt can contribute one extra blank line. Never treat
  # arbitrary file data, a prompt-like prefix or disconnect as a success.
  rows=[]
  for _ in range(6):
   while not self.term.buf:self.term._more()
   while len(self.term.buf)<len(ROOT_PROMPT) and ROOT_PROMPT.startswith(self.term.buf):
    self.term._more()
   if self.term.buf.startswith(ROOT_PROMPT):
    self.term.exact(ROOT_PROMPT);break
   line=self.term.line();need(len(line)<1024,'unexpected R1 line')
   rows.append(line.decode('ascii'))
  else:raise Stop('INCONCLUSIVE','missing R1 terminal prompt')
  out='\n'.join(rows).strip();need(out and len(out)<4096,'empty/oversized R1 reply')
  rc=1 if any(x.startswith('ERR') for x in rows) else 0
  if cmd.startswith('apply-return ') and not rc:
   need(positive_handoff(out.removeprefix('WARN timeline-not-saved before updater launch\n')),'unrecognized handoff receipt')
  self.log.append(dict(utc=utc(),command=cmd,adapter_rc=rc,output=out,transport_sha256=self.sid));return rc,out
 def ok(self,cmd):
  rc,out=self.cmd(cmd);need(rc==0 and not out.startswith('ERR '),'unexpected '+cmd+' reply');return out
def sample(s):
 a=VR.fullmatch(s.ok('ver'));b=ST.fullmatch(s.ok('status'));c=VR.fullmatch(s.ok('ver'))
 need(a and b and c,'unexpected core/status wire format')
 need(a.groups()[:6]==c.groups()[:6] and a[3]=='3' and a[4]=='wb10','process or build drift')
 need(b[1]==a[5] and b[3]=='connected' and (b[5],b[6])==(a[6],a[1]),'status differs')
 need(int(a[7])<=int(b[2])<=int(c[7]) and int(c[7])>int(a[7]),'unexpected uptime')
 return dict(version=a[1],build=a[2],run=a[5],host_pin=s.fp,pin_file_sha256=s.pinhash,transport_sha256=s.sid)
def parse_state(line):
 m=re.fullmatch(r'r1 state=(none|authorized|expired|dispatched|returned) source_run=(-|[0-9A-F]{16}) nonce=(-|[0-9A-F]{32}) target=(-|\d{2}\.\d{2}) run=([0-9A-F]{16}) manifest=(-|[0-9a-f]{64})',line)
 need(m,'bad R1 status');return dict(zip(('state','source_run','nonce','target','run','manifest'),m.groups()))
def auth(s,snap,pk):
 need(snap['version']>='01.33' and snap['version']<pk['version'],'source cannot grant R1 for that version','NEEDS_OWNER')
 st=parse_state(s.ok('r1-status'))
 need(st['state']=='authorized','no current on-device approval','NEEDS_OWNER')
 need(st['source_run']==st['run']==snap['run'] and len(st['nonce'])==32 and st['target']==pk['version'] and st['manifest']==pk['manifest'],'authorization mismatch','REFUSED')
 need(s.ok('pending')=='pending-core: '+pk['receipt'],'pending receipt mismatch','REFUSED');return st
def returned(s,snap,b):
 pk=b['package'];old=b['source'];st=parse_state(s.ok('r1-status'));t=b['grant']
 need(snap['run']!=old['run'] and snap['build']==pk['build'] and snap['version']==pk['version'],'no expected new build/run')
 need(snap['host_pin']==old['host_pin'] and snap['pin_file_sha256']==old['pin_file_sha256'],'pin changed','TRUST_ERROR')
 need(st['state']=='returned' and st['source_run']==old['run'] and st['run']==snap['run'] and st['nonce']==t['nonce'] and st['target']==pk['version'] and st['manifest']==pk['manifest'],'no matching automatic listener proof')
 return st
def process(a):
 d=a.records.resolve();d.mkdir(parents=True,exist_ok=True);events=[];report={'phase':a.phase,'utc':utc(),'events':events};code=2
 try:
  if a.phase in ('preview','capture'):
   need(a.vpk and a.sha256 and a.build,'provide --vpk --sha256 --build');pk=local_package(a.vpk,a.sha256,a.build)
   if a.phase=='preview':
    report.update(verdict='PREVIEW_ONLY',package=pk);return 0
  if a.phase in ('submit','collect'):
   b=get(d/'physical-authorization.json')
   if a.phase=='submit':
    need(a.yes,'submit needs --yes; no request issued')
    need(not (d/'issued.json').exists(),'already issued; only collect')
   else:
    issued=get(d/'issued.json');need(issued['grant']==b['grant'] and issued['source']==b['source'],'different issued record')
    need(not (d/'refused.json').exists(),'apply-return was refused; obtain a new physical approval')
  with Session(events) as s:
   snap=sample(s);report['observed']=snap
   if a.phase=='observe':
    report['verdict']='OBSERVED_NOT_R1';code=0
   elif a.phase=='capture':
    st=auth(s,snap,pk);save(d/'physical-authorization.json',dict(utc=utc(),source=snap,grant=st,package=pk))
    report['verdict']='PHYSICAL_GRANT_CAPTURED';code=0
   elif a.phase=='submit':
    need(all(snap[k]==b['source'][k] for k in ('run','host_pin','pin_file_sha256','build','version')),'source changed')
    st=auth(s,snap,b['package']);need(st==b['grant'],'grant revoked or replaced','REFUSED')
    save(d/'issued.json',dict(utc=utc(),source=b['source'],grant=st))
    rc,msg=s.cmd('apply-return '+st['nonce'])
    if rc not in (0,-1) or msg.startswith('ERR'):
     save(d/'refused.json',dict(utc=utc(),rc=rc,reply=msg));raise Stop('REFUSED','do not retry this ticket')
    report['verdict']='SUBMITTED_NOT_PASS';code=0
   else:
    proof=returned(s,snap,b);report['proof']=proof
    need(a.no_owner_input,'matched technical proof; still need observation that nobody confirmed a system prompt')
    report['verdict']='PASS_R1';report['no_owner_input_attested']=True;code=0
 except Stop as e:report.update(verdict=e.code,reason=str(e))
 except Exception as e:report.update(verdict='INCONCLUSIVE',reason=type(e).__name__+': '+str(e)[:240])
 finally:
  f=d/(a.phase+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json');save(f,report)
  print(json.dumps({k:v for k,v in report.items() if k!='events'},ensure_ascii=True),'receipt:',f,flush=True)
 return code
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['preview','observe','capture','submit','collect']);p.add_argument('--records',type=Path,required=True);p.add_argument('--vpk',type=Path);p.add_argument('--sha256');p.add_argument('--build');p.add_argument('--yes',action='store_true');p.add_argument('--no-owner-input',action='store_true',help='collect only: explicitly attest no physical input after submitting this exact update');sys.exit(process(p.parse_args()))
