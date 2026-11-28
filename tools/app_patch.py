"""One title-specific Workbench patch. No arbitrary app paths, FTP or raw SSH exec.
check: local only. plan/apply: one pinned PTY; --reuse skips uploading.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, uuid
from pathlib import Path
import wbterm as w
TITLE,VERSION='RJGM52237','01.16'
BYTES=2944023
BOOT='db8dcb3fe45b069e2bc567e41e52e6f8e79e1c2fbeb8bc86da08c0f540c01597'
RECIPE='f0435af90d069a22d14acf8d855561ce134e1534ceb379a6c279d608d9ef1d79'
VPK='e3d9e38441e1239eb9eb43df6ab3ae420d0afa083bcffe9d5cbe0ec4e1fdf6ee'
SIGNER='SIGNER_SHA256'
N=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
def need(ok,msg):
    if not ok:raise ValueError(msg)
def incoming(path):
    need(re.fullmatch(r'ux0:/VITA-POC/(?!\.)(?![^/]*\.\.)[A-Za-z0-9_.-]{1,95}\.bin',path),'expected a flat .bin filename under ux0:/VITA-POC')
    return path
def message(run,path):
    need(re.fullmatch(r'[A-F0-9]{16}',run) and int(run,16),'invalid WB run')
    return f'WB-APP-PATCH-v1\nRUN {run}\nTITLE {TITLE}\nTARGET {VERSION}\nRECIPE {RECIPE}\nVPK {VPK}\nPATH {incoming(path)}\n'.encode('ascii')
def signature(msg):
    from standing_key_dpapi import load
    from cryptography.hazmat.primitives import hashes,serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec,utils
    key=load(Path(os.environ['LOCALAPPDATA'])/'VitaWorkbench/trust/standing-r1/release-p256.dpapi')
    need(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1),'wrong key type')
    point=key.public_key().public_bytes(ser.Encoding.X962,ser.PublicFormat.UncompressedPoint)
    need(hashlib.sha256(point).hexdigest()==SIGNER,'release signer differs from candidate')
    r,s=utils.decode_dss_signature(key.sign(msg,ec.ECDSA(hashes.SHA256())))
    return f'{r:064x} {min(s,N-s):064x}'
def perform(op,snap,reuse=None,*,opener=w.paired_terminal,sign=signature,notice=lambda s:print(s,file=sys.stderr,flush=True)):
    need(op in ('check','plan','apply') and snap.size==BYTES and snap.sha256==BOOT,'not the approved RJGM52237 01.13 eboot')
    if reuse:incoming(reuse)
    result={'operation':op,'title':TITLE,'target':VERSION,'bytes':BYTES,'eboot_sha256':BOOT,'recipe_sha256':RECIPE}
    if op=='check':return dict(result,state='LOCAL_VERIFIED_NO_DEVICE')
    path=incoming(reuse or f'ux0:/VITA-POC/RJGM52237-0116-{uuid.uuid4().hex[:16]}.bin')
    with opener() as t:
        identity=t.check()
        need((identity['version'],identity['build']) in {('02.16','02.16-live-turbo'),('02.17','02.17-live-shell'),('02.18','02.18-agent-ops'),('02.19','02.19-linux-term'),('02.20','02.20-turbo-term')},'requires a known device build with the matching 01.16 patch recipe')
        msg=message(identity['run'],path)
        if not reuse:
            got=t.push(snap,path)
            need(got==dict(action='put',remote=path,bytes=BYTES,sha256=BOOT),'upload unconfirmed; do not retry')
        notice('Incoming eboot: '+path+ (' (reuse requested; device must verify)' if reuse else ' (PUT receipt verified)'))
        command=f'app patch {op} {TITLE} {VERSION} {path}'
        if op=='apply':command+=' '+sign(msg)
        # Preserve error phase and never resend after an ambiguous submission.
        try:
            reply=t._app_transcript_and_exit(command,7200)
            rows=reply['stdout'].splitlines()
            errors=[x for x in rows if x.startswith('ERR ')]
            if errors and not any(x.startswith('OK ') for x in rows):
                detail='; '.join(errors)[:420]
                if 'outcome-unknown' in detail:raise w.Inconclusive(detail)
                raise w.DeviceRefused(detail+'; inspect before retry')
            lead='app-patch-plan' if op=='plan' else 'app-patch'
            mat=re.fullmatch(r'OK '+lead+r' title=RJGM52237 base=(01\.09|01\.10|01\.12|01\.13|01\.15) app_ver=01\.16 eboot_sha256='+BOOT,rows[0]) if len(rows)==1 else None
            need(mat and reply['shell_exit']==0 and reply['transport_sha256']==identity['transport_sha256'] and reply['host_sha256']==identity['host_sha256'],'missing or mismatched final patch receipt')
        except w.DeviceRefused:raise
        except Exception as e:
            raise w.Inconclusive(f'{op} result unknown; do not retry; inspect app status and stage: {e}') from e
        return dict(result,base=mat[1],state='VERIFIED_INSTALLED_TREE' if op=='apply' else 'VERIFIED_PLAN_NO_PROMOTE',
                    remote=path,uploaded=not bool(reuse),receipt=rows[0],identity=identity)
def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('operation',choices=['check','plan','apply'])
    cli.add_argument('eboot',type=Path);cli.add_argument('--reuse',metavar='INCOMING.bin',help='reuse an already uploaded incoming eboot; still check all hashes')
    a=cli.parse_args()
    try:
        with w.wb_tree.file_snapshot(a.eboot,BYTES) as snap:result=perform(a.operation,snap,a.reuse)
        print(json.dumps(result));return 0
    except (Exception,KeyboardInterrupt) as e:
        print(f'{type(e).__name__}: {e}; not retried',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
