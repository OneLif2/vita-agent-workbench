"""Explicitly submit one already-staged, previously signed Workbench update.

Default is offline preview. --submit only uses the original paired
interactive WB PTY. It never uploads, stages, restarts, or retries. A good
handoff receipt is not proof of the new Workbench run or of owner input.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import time

import auto_update_authorize as auth
import r1ctl
import stage_review as flow
import wbterm as wb

ACK="OK updater reused (detail=1), launching INAP00019; ssh will drop"
ACK_WARN="WARN timeline-not-saved before updater launch"
NONCE=re.compile(r"[0-9A-F]{32}")


@dataclass(frozen=True)
class Plan:
    scope: dict
    command: str
    source_build: str
    stage_transport: str
    records: Path


def local_plan(a):
    trust=auth.load_profile(a.profile,a.profile_sha256,a.fingerprint)
    scope,m=auth.package_scope(trust,a.stage,a.vpk,a.sha256)
    token=auth.json_unique(auth.read_small(a.token,8192))
    auth.verify_token(token,trust,scope,m)
    snapshot=auth.read_small(a.stage,65536)
    auth.require(auth.eq(auth.sha(snapshot),scope["stage_record_sha256"]),"stage witness changed")
    src=auth.json_unique(snapshot)["source"]
    parent=wb.wb_tree.source_path(a.stage).parent
    # Deterministic destination, not an arbitrary retry directory.
    target=scope["target"].replace(".","")
    manifest=scope["manifest_sha256"]
    records=parent/(f"standing-{scope['source_run']}-{target}-{manifest}")
    return Plan(scope,token["command"],src["build"],src["transport_sha256"],records)


def current_saved_pin():
    p,d=wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST,wb.PORT),wb.HOST,wb.PORT)
    return d,auth.sha(p.read_bytes())


def verify_source(t,pin,scope,plan):
    s=t.check()
    auth.require(s["channel"]=="one interactive PTY" and t.version==s["version"]==scope["source_version"] and
                 s["run"]==scope["source_run"] and s["build"]==plan.source_build and
                 auth.eq(s["host_sha256"],pin) and auth.eq(t.host_pin,pin) and
                 s["transport_sha256"]==t.transport_id!=plan.stage_transport and
                 auth.HEX.fullmatch(s["transport_sha256"]),"original paired source run/build/transport did not match")
    return s


def inspect_before(t,plan,rows,state=None):
    s=plan.scope;run=s["source_run"]
    auth.require(rows(t,"pending")==["pending-core: "+s["wbq2"]],"exact reviewed WBQ2 queue not present")
    auth.require(rows(t,"r1-auto-status")==["r1-auto state=enabled run="+run],"standing consent is not enabled")
    if state is not None:
        auth.require(rows(t,"r1-status")==[state],"grant changed since signed acknowledgment")
    auth.require(rows(t,"updater check")==["OK updater-check title=INAP00019 helper=reuse epoch=01.73 promote=0"],
                 "existing helper not verified for reuse")
    auth.require(flow.enough_power(rows(t,"ext sys")),"AC/battery preflight failed")


def issue(plan,*,paired=wb.paired_terminal,trust=current_saved_pin,rows=flow.reply):
    """Called only after independently validating the offline scope/signature."""
    s=plan.scope;run=s["source_run"];target=s["target"];manifest=s["manifest_sha256"]
    pin=trust()
    auth.require(auth.eq(pin[0],s["host_sha256"]),"existing Workbench pin is not original")
    auth.require(not os.path.lexists(plan.records),"prior record exists; do not retry")
    os.mkdir(plan.records) # Exclusive ledger before connecting; never cleared here.
    log=dict(scope=s,utc=flow.utc(),status="NOT_SUBMITTED",installed=False,apply_sent=False,sign_sent=False)
    try:
        with paired() as t:
            t.deadline=min(t.deadline,time.monotonic()+45)
            first=verify_source(t,pin[0],s,plan)
            log["source"]=first
            none=f"r1 state=none source_run=- nonce=- target=- run={run} manifest=-"
            inspect_before(t,plan,rows,none)
            auth.require(verify_source(t,pin[0],s,plan)==first and trust()==pin,"source changed before signed dispatch")
            command=auth.text(auth.COMMAND,plan.command,"invalid bounded signed request")
            flow.store(plan.records/"grant-issued.json",dict(utc=flow.utc(),scope=s,transport=first["transport_sha256"],
                       command_sha256=auth.sha(command.encode("ascii"))))
            log["sign_sent"]=None  # durable marker means a missing ACK cannot permit retry
            arm=rows(t,command)
            log["signed_reply"]=arm
            want=f"OK r1-signed target={target} run={run} manifest={manifest} grant=armed"
            if arm!=[want]:
                log["status"]="SIGNED_GRANT_REFUSED_OR_UNCONFIRMED_NO_RETRY"
                return 3,log
            log["sign_sent"]=True
            authrow=rows(t,"r1-status")
            auth.require(len(authrow)==1,"invalid grant readback")
            grant=r1ctl.parse_state(authrow[0])
            nonce=auth.text(NONCE,grant["nonce"],"invalid grant nonce",nonzero=True)
            auth.require(grant==dict(state="authorized",source_run=run,nonce=nonce,target=target,run=run,manifest=manifest),
                         "armed grant was not tied to approved source/receipt")
            inspect_before(t,plan,rows,authrow[0])
            auth.require(verify_source(t,pin[0],s,plan)==first and trust()==pin,"source changed before apply")
            flow.store(plan.records/"apply-issued.json",dict(utc=flow.utc(),grant=grant,scope=s,transport=first["transport_sha256"]))
            log["apply_sent"]=None
            out=rows(t,"apply-return "+nonce)
            log["apply_reply"]=out
            if out not in ([ACK],[ACK_WARN,ACK]):
                log["status"]="APPLY_REFUSED_OR_UNCONFIRMED_NO_RETRY"
                return 3,log
            log["apply_sent"]=True
            log["status"]="SUBMITTED_NOT_VERIFIED"
            return 0,log
    except Exception as ex:
        log["status"]="INCONCLUSIVE_NO_RETRY" if log["sign_sent"] is not False else "NOT_SUBMITTED"
        log["error"]=str(ex) if type(ex) is auth.Refused else type(ex).__name__
        return 3,log
    finally:
        # Failure to create the summary must never hide an already-issued
        # operation. The exclusive pre-send markers remain authoritative.
        try:flow.store(plan.records/"workflow.json",log)
        except Exception as ex:log["summary_write_error"]=type(ex).__name__


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    for name in ("profile","stage","vpk","token"):
        p.add_argument("--"+name,required=True,type=Path)
    for name in ("profile-sha256","fingerprint","sha256"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--submit",action="store_true",help="submit a single update using already-active standing owner consent")
    a=p.parse_args(argv)
    try:
        plan=local_plan(a)
        if not a.submit:
            result=dict(status="OFFLINE_PREVIEW",target=plan.scope["target"],installed=False,apply_sent=False)
            rc=0
        else:rc,result=issue(plan)
    except Exception as ex:
        rc,result=3,dict(status="NOT_SUBMITTED",installed=False,apply_sent=False,
                         reason=str(ex) if type(ex) is auth.Refused else type(ex).__name__)
    print(json.dumps(result,ensure_ascii=True))
    return rc


if __name__=="__main__":
    raise SystemExit(main())
