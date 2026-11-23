"""Read the configured Workbench over one pinned, owner-authenticated interactive PTY."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import time

import stage_review
import wbterm as wb
from check_in_place import ST,VR

MIN_NATIVE="01.86"
HEX=re.compile(r"[0-9a-f]{64}")
RUN=re.compile(r"[0-9A-F]{16}")
VERSION=re.compile(r"[0-9]{2}\.[0-9]{2}")
NUMBER=r"(?:0|[1-9][0-9]{0,19})"
HEADER=re.compile(r"OK wb-status version=([0-9]{2}\.[0-9]{2}) run=([0-9A-F]{16}) uptime_ms=("+NUMBER+r")")
STATE=re.compile(r"state wb=running lock=unknown overlay=(yes|no|unknown) foreground=(ready|blocked|unknown) "
                 r"focus_reason=(ok|callback|power|appmgr|overlay|rtc|rtc-zero|counters|rtc-gap|unknown)")
NETWORK=re.compile(r"network link=(connected|connecting|finalizing|disconnected|unknown) "
                   r"wifi=(connected|not-wifi|disconnected|unknown) ssh_listener=(listening|closed) ssh_session=paired")
UPDATE=re.compile(r"update queue=(pending|empty|unknown) target=([0-9]{2}\.[0-9]{2}|-) standing=(enabled|revoked|disabled|unknown)")
QUEUE=re.compile(r"pending-core: WBQ2 ([0-9]{2}\.[0-9]{2}) ([0-9a-f]{64}) ([1-9][0-9]{0,8})")
STANDING=re.compile(r"r1-auto state=(enabled|revoked|disabled) run=([0-9A-F]{16})")
MAX_U64=2**64-1
MAX_STAGE=32*1024*1024


class Invalid(ValueError):
    """The supposed health receipt was not tied to this pinned source/transport."""


def need(ok):
    if not ok:
        raise Invalid("unconfirmed status receipt")


def as_uint(text):
    need(bool(re.fullmatch(NUMBER,text)))
    n=int(text)
    need(n<=MAX_U64)
    return n


def unknown(reason):
    return dict(status="APP_UNKNOWN",source="none",reason=reason,app_running=None,version=None,build=None,run=None,
                uptime_ms=None,lock_screen="unknown",system_overlay="unknown",foreground_check="unknown",focus_reason="unknown",
                network_link="unknown",wifi="unknown",ssh_listener="unknown",ssh_session="unknown",
                wbq2_queue="unknown",wbq2_target=None,standing_update="unknown")


def saved_pin():
    path,pin=wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST,wb.PORT),wb.HOST,wb.PORT)
    return pin,hashlib.sha256(path.read_bytes()).hexdigest()


def identity(t, original):
    i=t.check()     # ver -> status -> ver (live readings, one paired interactive PTY).
    need(isinstance(i,dict) and i.get("channel")=="one interactive PTY" and t.host_pin==original
         and i.get("host_sha256")==original and i.get("transport_sha256")==t.transport_id
         and isinstance(t.transport_id,str) and HEX.fullmatch(t.transport_id)
         and isinstance(t.version,str) and VERSION.fullmatch(t.version) and i.get("version")==t.version
         and isinstance(i.get("run"),str) and RUN.fullmatch(i["run"]) and int(i["run"],16)
         and isinstance(i.get("build"),str) and re.fullmatch(re.escape(t.version)+r"-[0-9A-Za-z._-]{1,40}",i["build"]))
    return i


def parse_native(lines,i):
    need(isinstance(lines,list) and len(lines)==5 and lines[-1]=="END wb-status")
    h=HEADER.fullmatch(lines[0]);s=STATE.fullmatch(lines[1]);n=NETWORK.fullmatch(lines[2]);u=UPDATE.fullmatch(lines[3])
    need(h and s and n and u and (h[1],h[2])==(i["version"],i["run"]))
    need((u[1]=="pending")== (u[2]!="-"))
    need(u[2]=="-" or u[2]>h[1])
    need(n[2]=="unknown" or n[1]==("disconnected" if n[2]=="disconnected" else "connected"))
    need((s[2]=="ready")== (s[3]=="ok"))
    return dict(source="native_wb_status",uptime_ms=as_uint(h[3]),lock_screen="unknown",
                system_overlay={"yes":"present","no":"absent","unknown":"unknown"}[s[1]],
                foreground_check={"ready":"pass","blocked":"blocked","unknown":"unknown"}[s[2]],
                focus_reason=s[3],network_link=n[1],wifi=n[2],ssh_listener=n[3],
                ssh_session="paired",wbq2_queue=u[1],wbq2_target=None if u[2]=="-" else u[2],standing_update=u[3])


def legacy(t,i,rows=stage_review.reply):
    # Lack of an SSID/reply or a current non-foreground condition is not
    # proof of a locked screen, disconnected Wi-Fi, or a closed listener.
    q=rows(t,"pending")
    queue,target="unknown",None
    if q==["pending-core: no"]:
        queue="empty"
    elif len(q)==1:
        m=QUEUE.fullmatch(q[0])
        if m and int(m[2],16) and int(m[3])<=MAX_STAGE:
            queue,target="pending",m[1]
    st="unknown"
    if i["version"]>="01.84":
        raw=rows(t,"r1-auto-status")
        m=STANDING.fullmatch(raw[0]) if len(raw)==1 else None
        if m and m[2]==i["run"]:
            st=m[1]
    v=ST.fullmatch(t.one("status"))
    need(v and (v[1],v[3],v[6])==(i["run"],"connected",i["version"]))
    return dict(source="legacy_paired_status",uptime_ms=as_uint(v[2]),lock_screen="unknown",system_overlay="unknown",
                foreground_check="unknown",focus_reason="unknown",network_link="unknown",wifi="unknown",ssh_listener="unknown",
                ssh_session="paired",wbq2_queue=queue,wbq2_target=target,standing_update=st)


def paired_status(original):
    # wbterm checks the canonical saved Vita key before loading/offering the
    # owner key; retain the independently read snapshot to bind the receipt.
    return wb.paired_terminal()


def read_status(endpoint,*,paired=paired_status,trust=saved_pin,rows=stage_review.reply):
    """No retries, alternate transports, probing other ports, or launch."""
    if endpoint!=(wb.HOST,str(wb.PORT),wb.USER):
        return 78,unknown("unpaired_endpoint")
    try:
        anchor=trust()
        need(isinstance(anchor,tuple) and len(anchor)==2 and all(isinstance(x,str) and HEX.fullmatch(x) for x in anchor))
        original=anchor[0]
        with paired(original) as t:
            t.deadline=min(t.deadline,time.monotonic()+30)
            if not hmac.compare_digest(t.host_pin,original):
                raise wb.TrustRefused("authenticated status host is not the original pin")
            first=identity(t,original)
            if first["version"]>=MIN_NATIVE:
                data=parse_native(rows(t,"wb-status"),first)
            else:
                data=legacy(t,first,rows)
            need(identity(t,original)==first)
            final=t._transcript_and_exit("ver",timeout=8)
            need(final["command"]=="ver" and final["shell_exit"]==0 and final["host_sha256"]==original
                 and final["transport_sha256"]==t.transport_id)
            v=VR.fullmatch(final["stdout"].removesuffix("\n"))
            need(v and (v[1],v[2],v[5])==(first["version"],first["build"],first["run"])
                 and as_uint(v[7])>=data["uptime_ms"])
            if trust()!=anchor:
                raise wb.TrustRefused("saved Workbench pin changed during status")
        return 0,dict(status="OBSERVED",app_running=True,version=first["version"],build=first["build"],
                      run=first["run"],host_sha256=original,transport_sha256=first["transport_sha256"],**data)
    except (wb.TrustRefused,wb.pin.PairError):
        return 78,unknown("trust_refused")
    except ConnectionRefusedError:
        return 3,unknown("tcp_refused")
    except TimeoutError:
        return 3,unknown("timeout")
    except ImportError:
        return 3,unknown("client_dependency_unavailable")
    except Exception:
        return 3,unknown("status_unconfirmed")


def register(sub):
    p=sub.add_parser("status",allow_abbrev=False,help="read Workbench/lock/network/SSH/update state over the paired terminal")
    p.add_argument("--json",action="store_true",default=argparse.SUPPRESS,help="machine-readable status")


def command(args,endpoint):
    rc,j=read_status(endpoint)
    if args.json:
        print(json.dumps(j,ensure_ascii=True))
    elif rc:
        print("APP_UNKNOWN — Workbench run, lock and Wi-Fi cannot be verified ("+j["reason"]+").")
    else:
        print(f"WB running   {j['version']}   run {j['run']} ({j['source']})")
        print(f"lock={j['lock_screen']} overlay={j['system_overlay']} foreground={j['foreground_check']} reason={j['focus_reason']}")
        print(f"link={j['network_link']} wifi={j['wifi']} ssh-listener={j['ssh_listener']} ssh-session={j['ssh_session']}")
        print(f"WBQ2={j['wbq2_queue']} target={j['wbq2_target'] or '-'} standing={j['standing_update']}")
    return rc
