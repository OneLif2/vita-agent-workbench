"""Read-only, metadata-only crash index over the paired Workbench interactive PTY.

No FTP, SFTP, legacy exec, alternate host discovery, file download or retry.
Only a validated index is printable; malformed server text is not echoed.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import hmac
import json
import re
import time
import wbterm as wb

HEADER=re.compile(r"OK crash-index matched=(0|[1-9][0-9]{0,3}) shown=(0|[1-9][0-9]?) truncated=([01]) clock=device-local")
ROW=re.compile(r"crash name=(psp2core-[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,116}[A-Za-z0-9])?) modified=(unknown|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}) bytes=(0|[1-9][0-9]{0,19})")
ERROR=re.compile(r"ERR crash-index (usage|no-pty|nomem|open|read|close|scan-limit|metadata)")
HEX=re.compile(r"[a-f0-9]{64}")

class ProtocolError(Exception):
    pass

def check(ok,reason):
    if not ok: raise ProtocolError(reason)

def limit_arg(raw):
    if not isinstance(raw,str) or not re.fullmatch(r"[1-9][0-9]?",raw) or int(raw)>32:
        raise argparse.ArgumentTypeError("expected 1..32 (canonical decimal)")
    return int(raw)

def parse(stdout,limit):
    check(type(limit) is int and 1<=limit<=32,"invalid limit")
    check(isinstance(stdout,str) and 0<len(stdout)<=16384,"invalid index length")
    err=ERROR.fullmatch(stdout.removesuffix("\n"))
    if err: return dict(status="DEVICE_ERROR",reason=err[1])  # never an empty index
    lines=stdout.removesuffix("\n").split("\n")
    h=HEADER.fullmatch(lines[0])
    check(h is not None and lines[-1]=="END crash-index","invalid index envelope")
    matched,shown,truncated=(int(v) for v in h.groups())
    check(matched<=1024 and shown==min(matched,limit) and truncated==int(matched>shown) and len(lines)==shown+2,"invalid index counts")
    rows=[];seen=set()
    for line in lines[1:-1]:
        m=ROW.fullmatch(line)
        check(m is not None,"invalid index row")
        name,stamp,size=m.groups()
        check(len(name)<=127 and ".." not in name and name not in seen and int(size)<2**63,"invalid name or size")
        seen.add(name)
        if stamp!="unknown":
            try: year=datetime.fromisoformat(stamp).year
            except ValueError: raise ProtocolError("invalid device-local timestamp") from None
            check(year>=1980,"invalid device-local timestamp")
        rows.append(dict(name=name,modified=stamp,bytes=int(size)))
    # Unknown timestamps follow known entries. For equal times, use bytewise ASCII name.
    known=[r for r in rows if r['modified']!='unknown']
    ordered=sorted(sorted(known,key=lambda r:r['name']),key=lambda r:r['modified'],reverse=True)
    ordered+=sorted((r for r in rows if r['modified']=='unknown'),key=lambda r:r['name'])
    check(rows==ordered,"invalid device sort order")
    return dict(status="OK",clock="device-local",matched=matched,shown=shown,truncated=bool(truncated),
                entries=rows,title_attributed=False)

def existing_pin():
    _,digest=wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST,wb.PORT),wb.HOST,wb.PORT)
    return digest

def session_query(limit,explicit,paired=wb.paired_terminal,trust=existing_pin):
    check(type(limit) is int and 1<=limit<=32,"invalid limit")
    pin=trust()
    check(isinstance(pin,str) and HEX.fullmatch(pin),"invalid original pin")
    with paired() as t:  # wbterm verifies saved key before offering 5090's owner key
        t.deadline=min(t.deadline,time.monotonic()+25)
        check(hmac.compare_digest(pin,t.host_pin),"session host key changed")
        identity=t.check()  # same read-only ver → status → ver on this channel
        run=identity.get('run');ver=identity.get('version');sid=identity.get('transport_sha256')
        check(identity.get('host_sha256')==pin and identity.get('channel')=='one interactive PTY' and
              isinstance(run,str) and re.fullmatch('[0-9a-fA-F]{16}',run) and isinstance(sid,str) and
              HEX.fullmatch(sid) and sid==t.transport_id and isinstance(ver,str) and
              re.fullmatch('[0-9]{2}[.][0-9]{2}',ver) and t.version==ver,"invalid session identity")
        if ver<'01.80':return dict(status="UNSUPPORTED_CORE",version=ver,minimum='01.80',run=run)
        cmd='diag crashes'+(' --limit '+str(limit) if explicit or limit!=10 else '')
        r=t._transcript_and_exit(cmd,timeout=15)
        check(r['command']==cmd and r['shell_exit']==0 and r['host_sha256']==pin and
              r['transport_sha256']==sid and trust()==pin,"terminal receipt does not match session")
        result=parse(r['stdout'],limit)
        result.update(version=ver,run=run,host_sha256=pin,transport_sha256=sid)
        return result

def register(sub):
    diag=sub.add_parser('diag',help='read-only diagnostic metadata')
    ds=diag.add_subparsers(dest='diag_cmd',required=True)
    p=ds.add_parser('crashes',allow_abbrev=False,help='list top-level Vita crash-file metadata, newest first')
    p.add_argument('--limit',type=limit_arg,help='1..32; default 10 (32 when filtering by time)')
    p.add_argument('--since',metavar='DEVICE-LOCAL-TIME',help='inclusive device-local ISO timestamp; requires --until')
    p.add_argument('--until',metavar='DEVICE-LOCAL-TIME',help='inclusive device-local ISO timestamp; requires --since')
    p.add_argument('--json',action='store_true',default=argparse.SUPPRESS,help='machine-readable metadata')

def execute(args,endpoint,query=session_query):
    if endpoint!=(wb.HOST,str(wb.PORT),wb.USER):
        return 78,dict(status='TRUST_ERROR',reason='unpaired endpoint; no request sent')
    since,until=args.since,args.until
    if (since is None)!=(until is None):
        return 2,dict(status='INVALID_WINDOW',reason='--since and --until are required together')
    if since is not None:
        import crash_window
        try:crash_window.validate_window(since,until)
        except ValueError:return 2,dict(status='INVALID_WINDOW',reason='expected ordered device-local timestamps')
    limit=args.limit if args.limit is not None else (32 if since is not None else 10)
    try:
        result=query(limit,args.limit is not None)
        if result['status']!='OK':return 3,result
        if since is not None:
            result['window']=crash_window.classify(result['entries'],result['matched'],result['truncated'],since,until)
        return 0,result
    except ProtocolError as e:return 3,dict(status='INVALID_TRANSCRIPT',reason=str(e))
    except (wb.pin.PairError,wb.TrustRefused):return 78,dict(status='TRUST_ERROR')
    except (TimeoutError,OSError,wb.Inconclusive,wb.Refused,EOFError):return 3,dict(status='UNCONFIRMED',reason='terminal or receipt unavailable')
    except ImportError:return 127,dict(status='CLIENT_DEPENDENCY_MISSING')
    except Exception:return 3,dict(status='UNCONFIRMED',reason='terminal operation not confirmed')

def command(args,endpoint):
    rc,j=execute(args,endpoint)
    if args.json:print(json.dumps(j,ensure_ascii=True))
    elif rc:print(j['status']+(': '+j['reason'] if 'reason'in j else '')+(' (requires WB 01.80+)' if j['status']=='UNSUPPORTED_CORE' else ''))
    else:
        print(f"WB {j['version']} | {j['matched']} matching files, showing {j['shown']} | device-local time | metadata only; title not identified")
        for row in j['entries']:print(f"{row['modified']:19}  {row['bytes']:>12}  {row['name']}")
        if j['truncated']:print('List truncated: older or undated entries may be outside this view.')
        if 'window' in j:
            w=j['window'];print("Window "+w['status']+": "+", ".join(w['candidates'])+"; coverage="+w['coverage'])
    return rc
