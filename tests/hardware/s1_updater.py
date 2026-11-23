"""5090 S1 two-phase acceptance; only submit may switch Apps. Never re-pairs or relaunches on collect."""
from __future__ import annotations
from pathlib import Path
import argparse, datetime, hashlib, json, re, sys, time
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'tools'))
import wbctl as w
import pinned_check as pin
BUILD='01.34-live-s1';DEST='ux0:data/INAP00018/s1-selfcheck.txt'
ROWS=[('original',0,1),('changed',-8,0),('missing',-9,0),('extra',-9,0),('legacy',-14,0),('absent',-14,0),('seal-mismatch',-14,0),('not-newer',-6,0),('sfo-content',-8,0),('generated-head',-8,0),('payload-content',-8,0)]
VER=re.compile(r'wb version=01\.34 build=01\.34-live-s1 abi=3 proto=wb10 run=([0-9A-F]{16}) payload=\S+ uptime_ms=\d+')
def need(test,msg):
    if not test:raise ValueError(msg)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def record(d,name,obj):
    with (d/name).open('x',encoding='utf8') as f:json.dump(obj,f,ensure_ascii=False,indent=2);f.write('\n')
def load(d,name):return json.loads((d/name).read_text(encoding='utf8'))
def saved():
    need(w.HOST=='192.0.2.10' and int(w.PORT)==2222 and w.USER=='pi','unexpected endpoint')
    p,fp=pin.canonical_saved(pin.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))
    need(fp==json.loads((R/'evidence/physical-owner.json').read_text(encoding='utf8'))['host_fingerprint'],'unexpected pin')
    return dict(endpoint=f'{w.HOST}:{w.PORT}',fp=fp,pin_file_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
def remote(d,cmd,timeout=12):
    rc,o=w.ssh(cmd,timeout=timeout)
    with (d/'commands.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(dict(utc=utc(),command=cmd,rc=rc,combined=o))+'\n')
    print(f'[{rc}] {cmd}: {o}',flush=True)
    need(rc!=78,'host authentication failed; do not re-pair');return rc,o
def identity(d):
    rc,o=remote(d,'ver',8)
    if rc in (124,255):return None
    m=VER.fullmatch(o);need(rc==0 and m,'wrong or unavailable candidate')
    return m[1]
def submit(d):
    pairing=saved();d.mkdir(parents=True,exist_ok=False)
    run=identity(d);need(run,'device unavailable; submit not sent')
    rc,o=remote(d,'pending');need(rc==0 and o=='pending-core: no','existing queue or unreadable')
    rc,old=remote(d,'get '+DEST)
    need((rc==0 and 'ERR ' not in old) or (0<rc<125 and old.splitlines()[:1]==['ERR not-found']),'prior report not observable')
    need(f' run={run} ' not in old,'this boot already has a report; no duplicate selftest')
    need(identity(d)==run and saved()==pairing,'identity changed before request')
    record(d,'issued.json',dict(utc=utc(),command='s1-check',source_run=run,build=BUILD,trust=pairing,prior_rc=rc,prior=old))
    # Durable marker written before the single ever launch; never retry even if the reply is lost.
    rc,o=remote(d,'s1-check',45)
    record(d,'ack.json',dict(utc=utc(),rc=rc,combined=o))
    need(w.apply_observable(rc,o),'explicit refusal or unexpected launch receipt; do not relaunch')
    print('ISSUED: collect is read-only and never relaunches')
def matches(raw,run):
    rows=[f'S1-CHECK build={BUILD} run={run} fixture=isolated']
    rows += [f'{name} rc={rc} expected={rc} handoff={n} PASS' for name,rc,n in ROWS]
    rows += ['result=PASS tests=11/11 native_promote_calls=0 rc=0']
    need(raw.splitlines()==rows,'stale, incomplete, unexpected or failing isolated fixture result')
def collect(d,seconds):
    issued=load(d,'issued.json');pairing=issued['trust'];need(saved()==pairing,'pin drift')
    ack=d/'ack.json'
    if ack.exists():
        a=load(d,'ack.json');need(a['rc'] in (0,124,255) and 'ERR ' not in a['combined'],'prior launch refused, do not claim pass')
    stop=time.monotonic()+seconds
    while True:
        run=identity(d)
        if run and run!=issued['source_run']:break
        if time.monotonic()>=stop:raise ValueError('INCONCLUSIVE no new run yet; repeat collect only')
        time.sleep(4)
    rc,o=remote(d,'get '+DEST);need(rc==0,'no report from updater');matches(o,issued['source_run'])
    need(o!=issued['prior'],'old report');need(identity(d)==run and saved()==pairing,'run or key changed while collecting')
    rc,p=remote(d,'pending');need(rc==0 and p=='pending-core: no','unexpected queue after fixture')
    out=d/'RESULT.json'
    if out.exists():
        previous=load(d,'RESULT.json');need(previous['report']==o and previous['return_run']==run,'prior record differs')
        print('PASS (previous matching receipt retained)');return
    record(d,'RESULT.json',dict(result='PASS',scope='updater verifier on isolated fixture; not a production native promotion',physical=True,
           build=BUILD,utc=utc(),source_run=issued['source_run'],return_run=run,trust=pairing,report=o,native_promote_calls=0))
    print('PASS 11/11 physical isolated fixture, verified opener pin and returned run; native_promote_calls=0')
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('phase',choices=['submit','collect']);ap.add_argument('--records',type=Path,required=True);ap.add_argument('--timeout',type=int,default=100);a=ap.parse_args()
    try:
        need(1<=a.timeout<=300,'timeout must be 1..300')
        if a.phase=='submit':submit(a.records)
        else:collect(a.records,a.timeout)
    except (OSError,ValueError,KeyError) as ex:
        print('STOP:',ex,file=sys.stderr);sys.exit(2)

