"""Compile the source release's actual drain, main/startup→bind, inactive UI call.
All Vita I/O is stubbed. No device, sockets, CLI login, or hardware battery changes.
--probe-low uses the exact historical low sample and prints one deterministic JSON line.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
DEFAULT=HERE.parents[1]/'source'
LABEL='LOW BATTERY - CHARGE THEN REOPEN APP'
OLD='POWER EVENT - REOPEN APP'
CASES=['observed-low','low-log-write-fails','low-no-ac','low-invalid-sample','suspend-and-low',
       'normal','auto','auto-bad-panel','auto-bad-ack-input','auto-quick-veto','auto-r1-veto',
       'auto-r1-bad-veto-input','auto-focus-after','auto-bad-pair','manual-fresh','manual-cancel',
       'manual-ack-input-failed','manual-panel-failed','focus','callback','clock','late',
       'supply-change','repeat','flags','ac-mismatch']
REASONS={'low-log-write-fails':'low','low-no-ac':'low','low-invalid-sample':'low','suspend-and-low':'suspend',
    'manual-cancel':'cancel','manual-ack-input-failed':'ui','manual-panel-failed':'ui',
    'focus':'focus','callback':'callback','clock':'clock','late':'late','supply-change':'supply','repeat':'repeat','flags':'flags','ac-mismatch':'ac-mismatch'}
POST={'auto-quick-veto':('QUICK OPEN VETO',0),'auto-r1-veto':('R1 VETO OR EXPIRED',0),
      'auto-r1-bad-veto-input':('R1 VETO OR EXPIRED',0),'auto-focus-after':('FOCUS LOST AFTER POWER WATCH',0),
      'auto-bad-pair':('QUICK BIND REFUSED',1)}
def simple_hash(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def extract(body,a,b): return body[body.index(a):body.index(b,body.index(a))]
def function(body,signature):
    start=body.index(signature);opening=body.index('{',start);depth=1
    for end in range(opening+1,len(body)):
        depth+=(body[end]=='{')-(body[end]=='}')
        if depth==0:return body[start:end+1]
    raise ValueError('Unclosed production function: '+signature)
def test(src,cases,records):
    src=Path(src).resolve();prod=src/'vita_ssh_status.c'; text=prod.read_text(encoding='utf8')
    with tempfile.TemporaryDirectory(prefix='wbpowerprobe-') as scratch:
        p=Path(scratch);exe=p/('probe.exe' if os.name=='nt' else 'probe')
        parts={'drain.inc':extract(text,'static char pw_diag_source[','/* ---- network ---- */'),
               'inactive.inc':function(text,'static int inactive_screen('),
               'gate.inc':extract(text,'    const bool update_return = consumed','    if(remote_start)remote_start_installed_audit();')}
        assert 'wb_ssh_open(' in parts['gate.inc'] and 'net_setup()' in parts['gate.inc']
        assert 'idle_screen' not in parts['inactive.inc'] and 'static int inactive_screen(' in parts['inactive.inc']
        assert '(void)inactive_screen(reason);' in text[text.index('\nout:'):], 'main no longer calls inactive_screen(reason)'
        for name,frag in parts.items():(p/name).write_text(frag,encoding='utf8')
        build=['gcc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-I'+str(src),'-I'+str(p),str(HERE/'probe.c'),'-o',str(exe)]
        def op(argv):
            z=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=15)
            records.append(dict(argv=list(map(str,argv)),rc=z.returncode,stdout=z.stdout,stderr=z.stderr))
            if z.returncode:raise RuntimeError(z.stderr or z.stdout)
            return z.stdout
        op(build)
        return {s:json.loads(op([exe,s])) for s in cases}
def verify(obs,candidate):
    for s,o in obs.items():
        diag=REASONS.get(s,'-');net=opened=manual=ack=0;auto=int(s.startswith('auto'));wait=0;label=''
        if s=='observed-low':diag='low'
        if diag!='-': label=LABEL if candidate and s in ('observed-low','low-no-ac','low-log-write-fails') else OLD
        elif s in POST:label,net=POST[s]
        else:net=opened=1
        if s in ('manual-cancel','manual-fresh','manual-ack-input-failed','manual-panel-failed'):
            manual={'manual-cancel':2,'manual-fresh':3,'manual-ack-input-failed':1,'manual-panel-failed':1}[s]
            ack=manual if s!='manual-panel-failed' else 0;wait=1
        if auto and not candidate:
            manual=1;ack=0 if s=='auto-bad-panel' else 1;wait=1
            if s in ('auto-bad-panel','auto-bad-ack-input'):label=OLD;net=opened=0;diag='ui'
        expected=dict(label=label,net_setup_calls=net,ssh_open_calls=opened,diag=diag,power_prompts=manual,
                      ack_pad_reads=ack,auto_ack=auto,wait_ack_log=wait,
                      postgate_pad_reads=int(s in ('auto-r1-veto','auto-r1-bad-veto-input')))
        if candidate and (s in POST or s.startswith('manual')):
            # 02.18 agent-operated startup: a paired listener always uses the
            # automatic power acknowledgement; no R1/quick veto, owner prompt or
            # post-gate pad read remains. Low battery/suspend/focus/clock still stop.
            expected=dict(label='',net_setup_calls=1,ssh_open_calls=1,diag='-',power_prompts=0,
                          ack_pad_reads=0,auto_ack=1,wait_ack_log=0,postgate_pad_reads=0)
            label=''
        for k,v in expected.items():
            if o[k]!=v:raise AssertionError(f'{s}: {k}: expected {v!r}, actual {o!r}')
        assert bool(o['hint'])==bool(label)
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source',type=Path,default=DEFAULT)
    ap.add_argument('--baseline',type=Path);ap.add_argument('--probe-low',action='store_true');ap.add_argument('--evidence',type=Path)
    a=ap.parse_args();records=[];runs=[];rc=1
    try:
        if a.probe_low:
            print(json.dumps(test(a.source,['observed-low'],records)['observed-low'],separators=(',',':')))
        else:
            for path,candidate in [(a.baseline,False),(a.source,True)]:
                if path is None:continue
                obs=test(path,CASES,records);verify(obs,candidate)
                runs.append(dict(source=str(path.resolve()),sha256=simple_hash(path/'vita_ssh_status.c'),cases=obs))
                print(f'PASS {len(obs)} compiled {"candidate" if candidate else "baseline"} startup/power gate cases. No hardware, network or device-side operations.')
        rc=0
    finally:
        if a.evidence:
            a.evidence.write_text(json.dumps(dict(rc=rc,scope="Host SDK boundary simulation; no device/UI visibility claim",scenario="Run 5DE8ABEBD83AAD5E, quick=true, t_ms=1 inv=notify=cb=1 flags=0x1100 ac=1 low=1 suspend=0 focus=OK",runs=runs,commands=records),indent=2)+'\n',encoding='utf8')
    return rc
if __name__=='__main__':sys.exit(main())
