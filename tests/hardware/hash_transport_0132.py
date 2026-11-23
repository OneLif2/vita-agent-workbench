"""5090 read-only S2/S3 acceptance: reads a previously uploaded 01.32 VPK.

No put, install, queue, title launch, fault injection on live files, retry,
or re-pair. The --out path must be fresh. --dry-run does not connect.
"""
from __future__ import annotations
import argparse, datetime, hashlib, hmac, json, re, socket, subprocess, sys, threading, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import wbctl as w, pinned_check as pin

TAG="01.32-live-wbq2"
HASH_DIAG="OK hash-selftest normal=known empty=known oom=nomem partial=io-error failure_digest=none"
DENIED="ver unexpected-argument"
PUBLIC="HOST_SHA256"
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def require(ok,msg):
    if not ok:raise ValueError(msg)
def identity(text):
    m=re.fullmatch(r"wb version=01\.32 build=01\.32-live-wbq2 abi=3 proto=wb10 run=([A-F0-9]{16}) payload=\S+ uptime_ms=\d+",text.strip())
    require(m,"unexpected running version/build")
    return m[1]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--remote',required=True,help='known, already uploaded ux0:/VITA-POC/file.vpk')
    ap.add_argument('--sha256',required=True,help='independently verified VPK SHA-256')
    ap.add_argument('--local',type=Path,default=ROOT/'build/workbench_0132.vpk')
    ap.add_argument('--run',help='optional expected Workbench run ID')
    ap.add_argument('--out',type=Path,help='fresh JSON receipt, parent directory already exists')
    ap.add_argument('--dry-run',action='store_true',help='check hash, paths, registration only. No sockets.')
    a=ap.parse_args(); results={k:'INCONCLUSIVE' for k in ('S2','S3')};rows=[]
    d=dict(utc_start=utc(),results=results,rows=rows,pin_verified=False,build=TAG)
    if not a.dry_run and not a.out:ap.error('--out required')
    handle=a.out.open('x',encoding='utf8') if a.out else None
    stage='local_checks'
    def journal():
        if handle:
            handle.seek(0);json.dump(d,handle,indent=2);handle.write('\n');handle.truncate();handle.flush()
    def row(mode,cmd,rc,out,err):
        rows.append(dict(utc=utc(),client=mode,cmd=cmd,rc=rc,stdout=out,stderr=err));journal()
        print(f"{mode} [{rc}] {cmd}: {out.strip()[:180]} {err.strip()[:120]}",flush=True)
    def openssh(cmd):
        res=subprocess.run(pin.openssh_argv(w.HOST,int(w.PORT),w.KEY,w.USER)+[cmd],
                           stdin=subprocess.DEVNULL,capture_output=True,timeout=45)
        out=res.stdout.decode('utf8','replace');err=res.stderr.decode('utf8','replace')
        row('OpenSSH',cmd,res.returncode,out,err)
        require(not err.strip(),'unexpected OpenSSH stderr')
        return res.returncode,out.strip()
    try:
        require(re.fullmatch(r'ux0:/VITA-POC/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,75}\.vpk',a.remote),'invalid known incoming VPK path')
        require(re.fullmatch(r'[a-f0-9]{64}',a.sha256),'expected lowercase SHA-256')
        require(not a.run or re.fullmatch(r'[A-F0-9]{16}',a.run),'invalid optional run')
        raw=a.local.read_bytes();require(hashlib.sha256(raw).hexdigest()==a.sha256,'local hash mismatch')
        facts=w.vpk_facts(a.local);require((facts['title_id'],facts['app_ver'])==('INAP00018','01.32'),'not an 01.32 Workbench VPK')
        require((w.HOST,int(w.PORT),w.USER)==('192.0.2.10',2222,'pi'),'unexpected endpoint')
        ref=json.loads((ROOT/'evidence/physical-owner.json').read_text(encoding='utf8'))['host_fingerprint']
        path,fp=pin.canonical_saved(pin.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))
        require(fp==PUBLIC==ref,'unexpected saved pin')
        d.update(host_fingerprint=fp,pinfile_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),vpk_sha256=a.sha256,bytes=len(raw),remote=a.remote)
        if a.dry_run:
            d.update(verdict='DRY_RUN_NOT_DEVICE');journal();print('DRY_RUN_NOT_DEVICE');return 0
        stage='openssh_before'
        rc,v=openssh('ver');require(rc==0,'no authenticated OpenSSH version response')
        run=identity(v);require(not a.run or a.run==run,'initial run differs');d.update(pin_verified=True,run=run);journal()
        for cmd in ('plan','inspect'):
            stage='openssh_'+cmd;rc,reply=openssh(cmd+' '+a.remote)
            first=('plan ' if cmd=='plan' else '')+f'file bytes={len(raw)} sha256={a.sha256}'
            require(rc==0 and reply.splitlines()[:1]==[first] and not any(x.startswith('ERR') for x in reply.splitlines()),cmd+' digest/exit mismatch')
        stage='device_fixed_hash_tests';rc,reply=openssh('hash-selftest')
        require((rc,reply)==(0,HASH_DIAG),'isolated device hash tests failed')
        results['S2']='PASS';journal()
        stage='openssh_denial';rc,reply=openssh(DENIED)
        require((rc,reply)==(125,'ERR denied command'),'missing explicit OpenSSH denial')
        stage='cli_json';p=subprocess.run([sys.executable,'-B',str(ROOT/'tools/wbctl.py'),'--json','deny-check'],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=35)
        row('wbctl/strict OpenSSH','--json deny-check',p.returncode,p.stdout,p.stderr)
        require(p.returncode==0 and not p.stderr.strip(),'wbctl did not confirm strict denial')
        parsed=json.loads(p.stdout);require((parsed['classification'],parsed['reason'],parsed['ssh_exit'])==('denied','command',125),'wrong CLI classification')

        stage='paramiko_import';import paramiko
        stage='paramiko_connect'
        with socket.create_connection((w.HOST,int(w.PORT)),timeout=6) as sock:
            tr=paramiko.Transport(sock);timer=threading.Timer(50,tr.close);timer.daemon=True;timer.start()
            try:
                stage='paramiko_key_exchange';tr.banner_timeout=7;tr.auth_timeout=7;tr.start_client(timeout=8)
                k=tr.get_remote_server_key()
                require(k.get_name()==pin.ALGO and hmac.compare_digest(hashlib.sha256(k.asbytes()).hexdigest(),fp),'host key mismatch; no key offered')
                stage='paramiko_auth';tr.auth_publickey(w.USER,paramiko.ECDSAKey.from_private_key_file(str(w.KEY)))
                require(tr.is_active() and tr.is_authenticated(),'owner authentication failed')
                session=bytes(tr.session_id);require(bool(session),'missing session ID')
                d['paramiko_transport_sha256']=hashlib.sha256(session).hexdigest()
                def request(cmd):
                    nonlocal stage
                    stage='paramiko_channel_open:'+cmd
                    with tr.open_session(timeout=6) as ch:
                        ch.settimeout(6);stage='paramiko_exec_ack:'+cmd;ch.exec_command(cmd)
                        stage='paramiko_channel_reply:'+cmd;until=time.monotonic()+7;o=bytearray();e=bytearray()
                        while True:
                            if ch.recv_ready():o.extend(ch.recv(2048))
                            if ch.recv_stderr_ready():e.extend(ch.recv_stderr(2048))
                            require(len(o)+len(e)<8192,'unexpected output length')
                            if ch.closed and not ch.recv_ready() and not ch.recv_stderr_ready():break
                            require(time.monotonic()<until,'reply timeout');time.sleep(.01)
                        require(ch.exit_status_ready(),'missing exit status')
                        rc=ch.recv_exit_status();out=o.decode('utf8','replace');err=e.decode('utf8','replace')
                        row('Paramiko:single-transport',cmd,rc,out,err)
                        require(not err.strip(),'remote stderr')
                        return rc,out.strip()
                rc,v=request('ver');require(rc==0 and identity(v)==run,'Paramiko unexpected run')
                rc,v=request(DENIED);require((rc,v)==(125,'ERR denied command'),'missing explicit Paramiko denial')
                rc,v=request('status');require(rc==0 and ('run='+run) in v.split() and 'ssh=connected' in v.split() and 'core=01.32' in v.split(),'status after denial missing')
                rc,v=request('ver');require(rc==0 and identity(v)==run,'different run after denial')
                require(tr.is_active() and tr.is_authenticated() and hmac.compare_digest(bytes(tr.session_id),session),'did not retain same Paramiko transport')
            finally:timer.cancel();tr.close()
        require(pin.canonical_saved(pin.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))[1]==fp and hashlib.sha256(path.read_bytes()).hexdigest()==d['pinfile_sha256'],'saved pairing changed')
        results['S3']='PASS';d['verdict']='PASS';return 0
    except Exception as exc:
        d.update(verdict='INCONCLUSIVE',failed_stage=stage,error_type=type(exc).__name__,detail=str(exc))
        print('STOP',stage,type(exc).__name__,str(exc),file=sys.stderr)
        return 2
    finally:
        d['utc_end']=utc();journal()
        if handle:handle.close()
        print('results',json.dumps(results))
if __name__=='__main__':sys.exit(main())
