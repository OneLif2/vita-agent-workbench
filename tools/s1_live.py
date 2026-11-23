"""Attended S1 field test. One pinned SSH transport per phase. No R1, no repair of receipts.
old: try approved update once from stock 01.33. bridge: upload trace VPK only on stock core.
retry: repeat install from 01.33-live-s1trace without repeating 01.33->01.34 version bypass.
apply: separate once-only launch after the verified WBQ2 queue. observe: read-only."""
import argparse,datetime,hashlib,json,os,re,sys,time,zipfile
from pathlib import Path
import r1ctl as r,wbctl as w,space_budget
R=Path(__file__).resolve().parents[1]
D=R/'evidence/live/s1'
OLD='01.33-live-r1';TRACE='01.33-live-s1trace';NEW='01.34-live-s1'
def check(ok,why):
 if not ok:raise RuntimeError(why)
def line(d,name,**v):
 with (d/name).open('a',encoding='utf8') as f:
  f.write(json.dumps(dict(utc=r.utc(),**v))+'\n');f.flush();os.fsync(f.fileno())
def once(d,name,**v):r.save(d/name,dict(utc=r.utc(),**v))
def data(p):return r.get(p)
def package(bridge):
 key='trace' if bridge else 'core'
 q=sorted((R/'build').glob('jetson-'+key+'-*.json'))[-1]
 j=data(q)['result'];p=R/'build'/('workbench_0133_s1_trace.vpk' if bridge else 'workbench_0134.vpk')
 check(Path(j['path']).resolve()==p.resolve(),'unknown build')
 tag=TRACE if bridge else NEW
 pk=r.local_package(p,j['sha256'],tag);blob=p.read_bytes();check(r.sha(blob)==j['sha256'] and len(blob)==j['bytes'],'package drift')
 return p,pk,blob
def issue(s,c,blob=b''):
 if c in ('ver','status','pending'):return s.cmd(c)
 check(bool(re.fullmatch(r'(?:df [0-9]+|put ux0:/VITA-POC/wb(?:0134|trace)-[0-9a-f]{12}\.vpk [0-9]+ sha256=[0-9a-f]{64}|inspect ux0:/VITA-POC/wb(?:0134|trace)-[0-9a-f]{12}\.vpk|inspect ux0:data/INAP00018/stage/pkg/(?:eboot\.bin|workbench_payload\.suprx|sce_sys/param\.sfo|sce_sys/package/head\.bin)|install ux0:/VITA-POC/wb0134-[0-9a-f]{12}\.vpk sha256=[0-9a-f]{64} --no-reload|apply-core|get ux0:data/INAP00018/(?:updater\.log|run\.log)|start-status)',c)),'not a deployment command')
 check(s.tr.is_active() and s.tr.is_authenticated() and r.sha(bytes(s.tr.session_id))==s.sid,'transport changed')
 time.sleep(.25)  # allow Vita libssh to service the previous channel-close
 buf=bytearray();err=bytearray();end=time.monotonic()+100
 with s.tr.open_session(timeout=8) as ch:
  ch.settimeout(15);ch.exec_command(c)
  if blob:
   ch.sendall(blob);ch.shutdown_write()
  while not (ch.closed and not ch.recv_ready() and not ch.recv_stderr_ready()):
   check(time.monotonic()<end,'command timeout')
   if ch.recv_ready():buf.extend(ch.recv(8192))
   if ch.recv_stderr_ready():err.extend(ch.recv_stderr(2048))
   check(len(buf)+len(err)<=2097152,'response limit');time.sleep(.005)
  rc=ch.recv_exit_status();out=buf.decode('utf8','replace').strip();stderr=err.decode('utf8','replace')
 s.log.append(dict(utc=r.utc(),command=c,rc=rc,output=out,stderr=stderr,transport_sha256=s.sid))
 print('rc',rc,c,'=>',out[-850:],flush=True);check(not stderr,'unexpected SSH channel stderr')
 return rc,out
def perform(phase):
 D.mkdir(parents=True,exist_ok=True);events=[];outcome='INCONCLUSIVE';extra={};code=2
 try:
  if phase!='observe':
   check(data(R/'evidence/HOST.json')['passed'],'main host gate not passed')
   for name in ('s1-seal-candidate.json','s1-calibration-host.json'):check((R/'evidence'/name).is_file(),'missing S1 host evidence')
  with r.Session(events) as s:
   snap=r.sample(s);extra['observed']=snap
   print('current',snap['build'],snap['run'],flush=True)
   if phase=='observe':
    if snap['build'] in (NEW,TRACE):
     rc,msg=issue(s,'get ux0:data/INAP00018/run.log')
     extra['startup_routes']=[l for l in msg.splitlines() if rc==0 and l.startswith('run='+snap['run']+' ') and ('QUICK ' in l or 'R1 RETURN' in l or 'LISTENING ' in l)]
    if snap['build']==NEW and (D/'issued.json').exists():
     b=data(D/'issued.json')['source'];check(snap['run']!=b['run'] and snap['host_pin']==b['host_pin'] and snap['pin_file_sha256']==b['pin_file_sha256'],'return mismatch')
     rc,q=issue(s,'pending');check((rc,q)==(0,'pending-core: no'),'queue not cleared')
     rc,o=issue(s,'get ux0:data/INAP00018/updater.log');extra['updater_tail']=o.splitlines()[-18:] if not rc else []
     outcome='NEW_BUILD_NEW_RUN_QUEUE_CLEAR_NOT_R1'
    else:outcome='OBSERVED'
   else:
    p,pk,blob=package(phase=='bridge')
    remote='ux0:/VITA-POC/'+('wbtrace-' if phase=='bridge' else 'wb0134-')+pk['vpk_sha256'][:12]+'.vpk'
    extra.update(package=pk,remote=remote)
    if phase in ('old','baseline','retry','bridge'):
     check(snap['build']==(TRACE if phase=='retry' else OLD),'unexpected source build')
     if phase=='bridge':check((D/'old-refused.json').is_file(),'no prior unchanged-source failure')
     if phase=='retry':
      ref=data(D/'baseline-refused.json')
      check(ref['package']==pk and snap['run']!=ref['source']['run'],'same refused VPK and new trace run required')
     check(issue(s,'pending')==(0,'pending-core: no'),'different or existing queued update; no stage change')
     check(space_budget.probe(lambda c:issue(s,c),space_budget.requirement(w.vpk_facts(p))['required'])['ok'],'space preflight failed')
     sha=pk['vpk_sha256'];ready=D/(remote.split('/')[-1]+'.verified.json')
     if not ready.exists():
      once(D,remote.split('/')[-1]+'.upload-intent.json',remote=remote,sha=sha,source=snap)
      rc,q=issue(s,f'put {remote} {len(blob)} sha256={sha}',blob)
      check(rc==0 and q==f'OK put path={remote} bytes={len(blob)} sha256={sha}','upload refused')
     rc,o=issue(s,'inspect '+remote)
     check(rc==0 and f'file bytes={len(blob)} sha256={sha}' in o.splitlines() and f'title_id=INAP00018 app_ver={pk["version"]} title=Vita Agent Workbench' in o.splitlines(),'VPK inspect failed')
     if not ready.exists():once(D,ready.name,remote=remote,sha=sha)
     if phase=='bridge':outcome='TRACE_VPK_READY_FOR_ATTENDED_INSTALL'
     else:
      once(D,phase+'-install-intent.json',source=snap,remote=remote,package=pk)
      rc,o=issue(s,f'install {remote} sha256={sha} --no-reload')
      if rc!=0 or 'ERR ' in o:
       once(D,phase+'-refused.json',source=snap,package=pk,rc=rc,output=o);outcome='INSTALL_REFUSED'
       with zipfile.ZipFile(p) as z:
        for item in ('eboot.bin','sce_sys/param.sfo','sce_sys/package/head.bin','workbench_payload.suprx'):
         code1,text=issue(s,'inspect ux0:data/INAP00018/stage/pkg/'+item)
         m=re.search(r'file bytes=(\d+) sha256=([0-9a-f]{64})',text)
         if item in z.namelist() and m:extra.setdefault('stage_members',{})[item]=r.sha(z.read(item))==m[2]
       extra['pending_after_failure']=issue(s,'pending');raise RuntimeError('install refused; no apply')
      check(any(x.startswith('OK install version=01.34 title=INAP00018 ') and 'core=queued session=kept' in x for x in o.splitlines()),'unexpected install reply')
      check(issue(s,'pending')==(0,'pending-core: '+pk['receipt']),'real and local WBQ2 differ')
      once(D,'staged.json',source=snap,package=pk,output=o)
      outcome='QUEUED_VERIFIED_SAME_TRANSPORT'
    else:
     b=data(D/'staged.json');check(snap['build']==b['source']['build'] and snap['run']==b['source']['run'] and pk==b['package'],'not the recorded source/package')
     check(issue(s,'pending')==(0,'pending-core: '+pk['receipt']),'receipt changed')
     once(D,'issued.json',source=snap,package=pk,command='apply-core',never_retry=True)
     rc,o=issue(s,'apply-core');check(rc==0 and w.positive_handoff(o),'not a positive updater reply; never resend')
     outcome='UPDATER_ACCEPTED_NOT_A_PASS'
   code=0
 except Exception as ex:extra['error']=type(ex).__name__+': '+str(ex)
 finally:
  initial=D/(phase+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
  r.save(initial,dict(utc=r.utc(),phase=phase,outcome=outcome,events=events,**extra))
  print(outcome,extra.get('error',''),initial,flush=True)
 return code
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('phase',choices=['observe','old','baseline','bridge','retry','apply']);sys.exit(perform(ap.parse_args().phase))
