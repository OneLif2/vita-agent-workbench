"""5090 read-only WBQ2 comparison. Result is not an R1 grant or a screen/installation proof."""
from __future__ import annotations
import argparse
import hmac
import json
from pathlib import Path
import re
import time
import wbterm as wb

HEX=re.compile(r'[0-9a-f]{64}')
RUN=re.compile(r'[0-9A-F]{16}')
VER=re.compile(r'[0-9]{2}[.][0-9]{2}')
WBQ=re.compile(r'WBQ2 ([0-9]{2}[.][0-9]{2}) ([0-9a-f]{64}) ([1-9][0-9]{0,8})')
TITLE='INAP00018'

class ReviewError(Exception):
    def __init__(self,state,why):
        self.state=state
        super().__init__(why)

def check(ok,why,state='MISMATCH'):
    if not ok:raise ReviewError(state,why)

def groups(digest):
    check(isinstance(digest,str) and HEX.fullmatch(digest),"invalid manifest")
    return [digest[i:i+8].upper() for i in range(0,64,8)]

def unit(obj,key,pattern):
    val=obj.get(key)
    check(isinstance(val,str) and pattern.fullmatch(val),'invalid '+key)
    return val

def distinct(pairs):
    d={}
    for k,v in pairs:
        check(k not in d,'ambiguous local stage record','LOCAL_ERROR');d[k]=v
    return d

def load_expected(vpk,approved,stage,compiler=None):
    # The SHA argument must come from the trusted local build/release, never the Vita.
    # r1ctl.local_package independently checks the archive SHA, SFO title/version,
    # embedded build, and computes the native 4-member manifest (including derived head.bin).
    if compiler is None:
        from r1ctl import local_package as compiler
    check(isinstance(approved,str) and HEX.fullmatch(approved),'provide official lowercase VPK SHA-256','LOCAL_ERROR')
    with Path(stage).open('rb') as f:data=f.read(65537)
    check(0<len(data)<=65536,'invalid stage record size','LOCAL_ERROR')
    j=json.loads(data,object_pairs_hook=distinct)
    check(isinstance(j,dict) and j.get('result')=='STAGED_NOT_APPLIED','requires a confirmed, unapplied stage record','LOCAL_ERROR')
    p,s=j.get('package'),j.get('source')
    check(isinstance(p,dict) and isinstance(s,dict),'incomplete stage record','LOCAL_ERROR')
    v=unit(p,'version',VER);source=unit(s,'version',VER);run=unit(s,'run',RUN);pin=unit(s,'host_sha256',HEX)
    stage_sid=unit(s,'transport_sha256',HEX)
    check(isinstance(s.get('build'),str) and re.fullmatch(re.escape(source)+r'-[a-zA-Z0-9._-]{1,40}',s['build'])
          and s.get('channel')=='one interactive PTY' and j.get('idle_source_run')==run and source<v,'invalid source identity')
    check(isinstance(p.get('build'),str) and re.fullmatch(re.escape(v)+r'-[a-zA-Z0-9._-]{1,40}',p['build']),'invalid target build','LOCAL_ERROR')
    check(p.get('vpk_sha256')==approved,'local stage not for approved VPK')
    pk=compiler(Path(vpk),approved,p['build'])
    check(set(pk)=={'version','build','manifest','receipt','vpk_sha256'} and
          all(p.get(k)==val for k,val in pk.items()) and j.get('pending')==pk['receipt'],'stage vs freshly reconstructed local package')
    m=WBQ.fullmatch(pk['receipt'])
    check(m and m[1]==v and m[2]==pk['manifest'],'invalid local WBQ2')
    return dict(title=TITLE,version=v,build=p['build'],receipt=pk['receipt'],manifest=m[2],bytes=int(m[3]),
                groups=groups(m[2]),vpk_sha256=approved,source_version=source,source_build=s['build'],
                source_run=run,host_sha256=pin,stage_transport=stage_sid)

def existing_pin():
    _,pin=wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST,wb.PORT),wb.HOST,wb.PORT)
    return pin

def fixed_rows(t,cmd):
    # Only fixed, read-only, bounded native replies. A queue can contribute one extra LF.
    check(cmd in ('pending','r1-review'),'invalid review verb','UNCONFIRMED')
    t.command(cmd)
    lines=[]
    for _ in range(5):
        while not t.buf:t._more()
        while len(t.buf)<len(wb.ROOT_PROMPT) and wb.ROOT_PROMPT.startswith(t.buf):t._more()
        if t.buf.startswith(wb.ROOT_PROMPT):
            t.exact(wb.ROOT_PROMPT);return lines
        raw=t.line()
        check(len(raw)<=256 and all(32<=c<127 for c in raw),'invalid native reply','UNCONFIRMED')
        lines.append(raw.decode('ascii'))
    raise ReviewError('UNCONFIRMED','incomplete native reply')

def check_pending(lines,e):
    if lines==['pending-core: no']:raise ReviewError('NO_PENDING','no queued core')
    q='pending-core: '+e['receipt']
    check(lines in ([q],[q,'']),'Vita pending version, digest or byte total differs')

def checked_final(t,cmd,pin,sid,timeout=8):
    final=t._transcript_and_exit(cmd,timeout=timeout)
    check(final['command']==cmd and final['shell_exit']==0 and final['host_sha256']==pin and final['transport_sha256']==sid,
          'invalid final session','UNCONFIRMED')
    return final['stdout']

def verify(e,paired=wb.paired_terminal,trust=existing_pin,*,notice_issue=None):
    # Standalone review-digest never delivers a notice. Only the staging
    # pipeline supplies a durable, one-use issuance callback.
    notice={'status':'NOT_REQUESTED'}
    original=trust()
    check(isinstance(original,str) and HEX.fullmatch(original) and hmac.compare_digest(original,e['host_sha256']),'saved host differs from witnessed staging','TRUST_ERROR')
    with paired() as t:
        t.deadline=min(t.deadline,time.monotonic()+25)
        check(hmac.compare_digest(original,t.host_pin),'live host differs from original pin','TRUST_ERROR')
        src=t.check();sid=t.transport_id
        check(src.get('channel')=='one interactive PTY' and src.get('host_sha256')==original and src.get('transport_sha256')==sid
              and isinstance(sid,str) and HEX.fullmatch(sid) and sid!=e['stage_transport'],'not a fresh pinned interactive session','TRUST_ERROR')
        check((src.get('version'),src.get('build'),src.get('run'))==(e['source_version'],e['source_build'],e['source_run'])
              and t.version==src['version'],'source changed since confirmed staging')
        check(src['version']>='01.80','requires 01.80 or newer','UNSUPPORTED_SOURCE')
        no='r1 state=none source_run=- nonce=- target=- run='+e['source_run']+' manifest=-'
        check(t.one('r1-status')==no,'not an idle pre-approval review','NOT_PRE_APPROVAL')
        check_pending(fixed_rows(t,'pending'),e)
        if src['version']>='01.81':
            expected=f"OK r1-review model=local-review title={e['title']} target={e['version']} bytes={e['bytes']} source_run={e['source_run']}"
            out=fixed_rows(t,'r1-review')
            check(len(out)==2 and out[0]==expected,'device local-review model unavailable or identity mismatch')
            check(out[1]=='groups='+' '.join(e['groups']),'one or more local-review groups differ')
            level='LOCAL_REVIEW_MODEL'
        else:level='PAIRED_PENDING_ONLY'
        check(t.check()==src,'run/transport changed while verifying')
        check(t.one('r1-status')==no,'grant changed while verifying','NOT_PRE_APPROVAL')
        if notice_issue is None or src['version']<'01.82':
            check_pending(checked_final(t,'pending',original,sid).removesuffix('\n').split('\n'),e)
            if notice_issue is not None:notice={'status':'LEGACY_SOURCE'}
        else:
            check_pending(fixed_rows(t,'pending'),e)
            check(trust()==original,'local pin changed before notice','TRUST_ERROR')
            # Revalidate the only argument that will be written on the PTY.
            manifest=unit(e,'manifest',HEX)
            cmd='r1-notice '+manifest
            intent=dict(title=e['title'],target=e['version'],bytes=e['bytes'],source_run=e['source_run'],
                        source_version=src['version'],manifest=manifest,host_sha256=original,transport_sha256=sid)
            notice_issue(intent)   # Persist before dispatch; existing marker => no dispatch.
            try:
                out=checked_final(t,cmd,original,sid,timeout=15)
                ack=f"OK r1-notice title={e['title']} target={e['version']} bytes={e['bytes']} source_run={e['source_run']} manifest={manifest}"
                if out==ack+'\n':
                    notice=dict(status='ACKNOWLEDGED',**intent)
                elif re.fullmatch(r'ERR r1-notice (?:no-pty|usage|not-verified|mismatch|busy)\n',out):
                    notice=dict(status='REFUSED',**intent)
                else:
                    notice=dict(status='UNCONFIRMED',**intent)
            except Exception:
                # The peer may have accepted before the response was lost.
                # A read/EOF error is neither success nor permission to resend.
                notice=dict(status='UNCONFIRMED',**intent)
        check(trust()==original,'local pin changed during review','TRUST_ERROR')
    return dict(status='MATCH',evidence=level,groups_matched=8,groups=e['groups'],title=e['title'],target=e['version'],
                vpk_sha256=e['vpk_sha256'],manifest_sha256=e['manifest'],wbq2_bytes=e['bytes'],source_version=src['version'],
                source_run=e['source_run'],host_sha256=original,transport_sha256=sid,pixels_verified=False,
                approval='LOCAL_OWNER_REQUIRED',authorized_by_agent=False,applied=False,notice=notice)

def register(sub):
    p=sub.add_parser('review-digest',allow_abbrev=False,help='compare all 8 WBQ2 groups; read-only, not owner authorization')
    p.add_argument('--vpk',required=True,metavar='LOCAL-VPK')
    p.add_argument('--sha256',required=True,metavar='TRUSTED-LOCAL-VPK-SHA256')
    p.add_argument('--stage',required=True,metavar='LOCAL-STAGE-CONFIRMED.JSON')
    p.add_argument('--json',action='store_true',default=argparse.SUPPRESS)

def execute(args,endpoint,loader=load_expected,query=verify):
    try:
        check(endpoint==(wb.HOST,str(wb.PORT),wb.USER),'unpaired endpoint','TRUST_ERROR')
        try:e=loader(args.vpk,args.sha256,args.stage)
        except ReviewError:raise
        except Exception:raise ReviewError('LOCAL_ERROR','cannot rebuild WBQ2 from approved release and confirmed stage') from None
        return 0,query(e)
    except ReviewError as ex:return (78 if ex.state=='TRUST_ERROR' else 3),dict(status=ex.state,reason=str(ex),applied=False,authorized_by_agent=False)
    except (wb.pin.PairError,wb.TrustRefused):return 78,dict(status='TRUST_ERROR',applied=False,authorized_by_agent=False)
    except Exception:return 3,dict(status='UNCONFIRMED',applied=False,authorized_by_agent=False)

def command(args,endpoint):
    rc,d=execute(args,endpoint)
    if args.json:print(json.dumps(d,ensure_ascii=True))
    elif rc:print(d['status']+(': '+d['reason'] if 'reason' in d else ''))
    else:
        print(f"{d['status']} 8/8 [{d['evidence']}] {d['title']} / {d['target']} / {d['wbq2_bytes']} bytes")
        print(' '.join(d['groups']))
        print('Read-only comparison; not a screen capture. Only the owner can authorize this update on Vita.')
    return rc
