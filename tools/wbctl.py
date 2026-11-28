#!/usr/bin/env python3
"""wbctl — 5090 CLI for Vita Workbench.

Workbench operations use its paired terminal. The wake preflight can check
an independently enrolled WB-only receiver using its fixed readiness subsystem.
Design rules (see VITA-AGENT-ROADMAP.md):

* read-only commands never install, update or reboot anything;
* `update` prints the package plan first and refuses without --yes;
* "success" is only reported when the *new process* reports the target version
  and a new run id; a launched updater is not success;
* unknown subcommands are refused locally, never forwarded to the device.

Environment: WB_HOST (192.0.2.10), WB_PORT (2222), WB_KEY (~/.ssh/id_ecdsa_wb),
WB_USER (pi).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
import zipfile
from pathlib import Path

import wbctl_pty
from app_registry import Denied, approve, approve_file
import wb_tree
import space_budget as space
from check_in_place import BUILD as CORE_BUILD, VERSION as CORE_VERSION, Problem as CoreError, checked_ver, VR

HOST = os.environ.get("WB_HOST", "192.0.2.10")
PORT = os.environ.get("WB_PORT", "2222")
USER = os.environ.get("WB_USER", "pi")
KEY = os.environ.get("WB_KEY", str(Path.home() / ".ssh" / "id_ecdsa_wb"))
TITLE_ID = "INAP00018"
TESTAPP_ID = "INAP00020"
JOBS_DIR = Path(__file__).resolve().parent.parent / "evidence" / "jobs"

def ssh(cmd: str, timeout: float = 20.0, stdin_bytes: bytes | wb_tree.FileSource | None = None,
        *, progress_total: int | None = None) -> tuple[int, str]:
    """Compatibility result for an operation on a pinned interactive PTY (not SSH exec)."""
    if (HOST,str(PORT),USER)!=(wbctl_pty.t.HOST,str(wbctl_pty.t.PORT),wbctl_pty.t.USER):
        return 78,"ERR unpaired endpoint; refusing alternate transport"
    return wbctl_pty.exchange(cmd,timeout,stdin_bytes,progress_total)


# ---------------------------------------------------------------- sfo / vpk

def exec_outcome(rc: int, text: str) -> dict:
    """Classify what the pinned SSH client actually observed, not a root cause."""
    observation = text.strip()
    lower = observation.lower()
    reason = None
    if rc == 125 and re.fullmatch(r"ERR denied (admission|foreground|link|command)", observation):
        kind, reason = "denied", observation.split()[-1]
    elif rc == 0:
        kind = "remote_error" if any(l.startswith("ERR ") for l in observation.splitlines()) else "ok"
    elif rc == 78:
        kind = "trust_error"
    elif rc == 124 or (rc == 255 and ("timed out" in lower or "timeout" in lower)):
        kind = "timeout"
    elif rc == 255 and ("permission denied" in lower or "authentication failed" in lower):
        kind = "authentication_failed"
    elif rc == 255 and any(m in lower for m in ("connection closed", "closed by remote host", "connection reset", "broken pipe")):
        kind = "disconnected"
    elif rc == 255:
        kind = "transport_error"  # includes legacy exec-request/channel failure: do not guess
    elif rc == 127:
        kind = "client_error"
    else:
        kind = "remote_error"
    return dict(classification=kind, reason=reason, adapter_rc=rc, transport="interactive PTY", output=observation)

def parse_sfo(data: bytes) -> dict[str, str]:
    _, keyofs, valofs, count = struct.unpack_from("<4I", data, 4)
    out: dict[str, str] = {}
    for i in range(count):
        ko, fmt, length, _cap, vo = struct.unpack_from("<HHIII", data, 20 + i * 16)
        end = data.index(b"\0", keyofs + ko)
        key = data[keyofs + ko:end].decode("ascii", "replace")
        if fmt == 0x0204:
            out[key] = data[valofs + vo:valofs + vo + length].rstrip(b"\0").decode("utf-8", "replace")
    return out


def vpk_facts(path: Path) -> dict:
    with wb_tree.checked_open(path) as file:
        before=os.fstat(file.fileno()); size=before.st_size
        digest=wb_tree.file_digest(file,size); file.seek(0)
        facts = {"path":str(path), "bytes":size, "sha256":digest,
                 "members":[], "title_id":None, "app_ver":None, "title":None}
        with zipfile.ZipFile(file) as z:
            for info in z.infolist():
                facts["members"].append({"name": info.filename, "size": info.file_size, "crc": f"{info.CRC:08X}"})
            if "sce_sys/param.sfo" in z.namelist():
                info=z.getinfo("sce_sys/param.sfo")
                if not 20<=info.file_size<=65536 or info.flag_bits&1:
                    raise ValueError("invalid-sfo-size")
                with z.open(info) as source:
                    data=source.read(65537)
                if len(data)!=info.file_size: raise ValueError("invalid-sfo-size")
                sfo = parse_sfo(data)
                facts["title_id"] = sfo.get("TITLE_ID")
                facts["app_ver"] = sfo.get("APP_VER")
                facts["title"] = sfo.get("TITLE")
        if wb_tree.signature(os.fstat(file.fileno()))!=wb_tree.signature(before):
            raise ValueError('source changed during package analysis')
    return facts


def ver_fields(text: str) -> dict[str, str]:
    m = VR.fullmatch(text)
    if not m:
        return {}
    return {"version": m[1], "build": m[2], "run": m[5].upper(), "payload": m[6]}


# ---------------------------------------------------------------- commands

def cmd_ver(args) -> int:
    rc, out = ssh("ver")
    if args.json: print(json.dumps(exec_outcome(rc, out)))
    else: print(out or f"ERR ssh rc={rc}")
    return 0 if rc == 0 and "wb version=" in out else 1


def cmd_deny_check(args) -> int:
    """A fixed invalid arity on a read-only command; no shell or arbitrary exec."""
    rc, out = ssh("ver unexpected-argument")
    evidence = exec_outcome(rc, out)
    # A PTY shell parser error is not an SSH exec channel rejection/125.
    denied = rc==1 and out=="ERR invalid or disallowed Workbench command/options"
    evidence.update(classification="terminal_command_denied" if denied else evidence["classification"],
                    layer="terminal parser",transport="interactive PTY")
    print(json.dumps(evidence) if args.json else out)
    return 0 if denied else 1


def cmd_timeline(args) -> int:
    lines = fetch_timeline()
    if not lines:
        print("timeline empty")
        return 1
    print("\n".join(lines))
    return 0


def fetch_timeline() -> list[str]:
    """Read the raw file: the device-side dump still mangles the last line."""
    rc, out = ssh("get ux0:data/INAP00018/timeline.txt")
    if rc == 0 and "stage=" in out:
        return [l for l in out.splitlines() if l.startswith("stage=")]
    rc, out = ssh("timeline")
    return [l for l in out.splitlines() if l.startswith("stage=")]


def upgrade_state(lines: list[str]) -> str:
    """queued -> updater -> boot. Verified only when a later boot reports the
    queued version from a different run id."""
    queued = [l for l in lines if l.startswith("stage=queued")]
    if not queued:
        return "idle"
    last = queued[-1]
    qver = re.search(r"ver=(\S+)", last).group(1)
    qrun = re.search(r"run=(\S+)", last).group(1)
    for line in reversed(lines):
        if not (line.startswith("stage=boot") or line.startswith("stage=verified")):
            continue
        bver = re.search(r"ver=(\S+)", line).group(1)
        brun = re.search(r"run=(\S+)", line).group(1)
        if bver == qver and brun != qrun:
            return f"verified {qver} (queued run {qrun}, now {brun})"
    return f"queued {qver} (run {qrun}) - no new boot yet"


def cmd_doctor(args) -> int:
    report: dict = {"host": f"{HOST}:{PORT}"}
    rc, out = ssh("ver")
    report["reachable"] = rc == 0 and "wb version=" in out
    report["ver_raw"] = out
    report["ver_exec"] = exec_outcome(rc, out)
    report["ver"] = ver_fields(out)
    if report["reachable"]:
        report["storage"]=space.probe(ssh,0)
        _, p = ssh("pending")
        report["pending"] = p
        lines = fetch_timeline()
        report["timeline_tail"] = lines[-8:]
        report["upgrade"] = upgrade_state(lines)
        _, s = ssh("status")
        report["status"] = s
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"device      {report['host']}")
        print(f"reachable   {report['reachable']}")
        v = report["ver"]
        if v:
            print(f"core        {v['version']}   build {v['build']}   run {v['run']}   payload {v['payload']}")
        if "storage" in report: print("storage     "+space.display(report["storage"]))
        if report.get("pending"):
            print(f"queue       {report['pending']}")
        print(f"upgrade     {report.get('upgrade', 'idle')}")
        for line in report.get("timeline_tail", []):
            print(f"timeline    {line}")
        if not report["reachable"]:
            print("next        arm Workbench (X, X) and check the host key pin")
    return 0 if report["reachable"] else 1


def cmd_plan(args) -> int:
    pkg = Path(args.vpk)
    if not pkg.is_file():
        print(f"ERR not-found {pkg}")
        return 2
    facts = vpk_facts(pkg)
    rc, out = ssh("ver")
    v = ver_fields(out) if rc == 0 else {}
    running = v.get("version")
    verdict = "unknown"
    if facts["app_ver"] and running:
        verdict = "newer" if facts["app_ver"] > running else "same" if facts["app_ver"] == running else "older"
    title_ok = facts["title_id"] == TITLE_ID
    needed=space.requirement(facts,getattr(args,"reserve_bytes",0))
    storage=space.probe(ssh,needed["required"])
    core_action = "replace" if verdict == "newer" else "keep"
    payload_member = any(m["name"] == "workbench_payload.suprx" for m in facts["members"])
    if args.json:
        print(json.dumps({**facts, "running": running, "verdict": verdict, "title_ok": title_ok, "space_budget":needed,"storage":storage}, indent=2, ensure_ascii=False))
        return 0 if title_ok and storage["ok"] else 1
    print("storage     "+space.display(storage))
    print(f"file        {facts['path']}")
    print(f"bytes       {facts['bytes']}")
    print(f"sha256      {facts['sha256']}")
    print(f"title       {facts['title_id']} / {facts['app_ver']}  ({facts['title']})")
    print(f"running     {running or 'unreachable'}")
    print(f"verdict     {verdict}   title_ok={title_ok}")
    print(f"action      core={core_action}  payload={'replace' if payload_member and verdict != 'older' else 'keep'}  queue={'yes' if verdict == 'newer' else 'no'}")
    for m in facts["members"]:
        print(f"member      {m['name']} size={m['size']} crc={m['crc']}")
    if not title_ok:
        print("ERR title-mismatch: only INAP00018 packages may be installed here")
        return 1
    return 0 if storage["ok"] else 1


def wait_for_version(target: str, old_run: str, timeout: float) -> tuple[str, str]:
    """Poll `ver` until the target version answers from a new run id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out = ssh("ver", timeout=max(.01,min(10.,deadline-time.monotonic())))
        if rc == 78:
            return "inconclusive", out
        if rc == 0:
            v = ver_fields(out)
            if v.get("version") == target and v.get("run") != old_run:
                return "verified", out
            if v.get("version") and v.get("run") != old_run:
                return "inconclusive", out
        time.sleep(max(0,min(3.,deadline-time.monotonic())))
    return "timeout", ""

def positive_handoff(out):
    # Accept only a complete native receipt, not a prefix or mismatched status/detail.
    return out in ("OK updater installed (detail=0), launching INAP00019; ssh will drop",
                   "OK updater reused (detail=1), launching INAP00019; ssh will drop")

def apply_observable(rc, out):
    # Loss means observe once (never means installation). Explicit refusal wins.
    return (rc in (124,255) and not any(v.startswith('ERR ') for v in out.splitlines())) or (
        rc==0 and positive_handoff(out))


def cmd_update(args) -> int:
    pkg = Path(args.vpk)
    if not pkg.is_file():
        print(f"ERR not-found {pkg}")
        return 2
    facts = vpk_facts(pkg)
    if facts["title_id"] != TITLE_ID:
        print(f"ERR title-mismatch {facts['title_id']} != {TITLE_ID}")
        return 2

    rc, out = ssh("ver")
    if rc!=0 or not ver_fields(out):
        print("ERR no verified baseline: "+out); return 3
    before = ver_fields(out)
    running = before.get("version", "")
    verdict = "newer" if running and facts["app_ver"] > running else ("same" if facts["app_ver"] == running else "older")
    print(f"plan        title={facts['title_id']} app_ver={facts['app_ver']} running={running or '?'} verdict={verdict}")
    print(f"plan        core={'replace' if verdict == 'newer' else 'keep'} queue={'yes' if verdict == 'newer' else 'no'}")
    if verdict != "newer" and not args.force:
        print("ERR not-newer: install requires a newer version")
        return 3
    needed=space.requirement(facts,getattr(args,"reserve_bytes",0))
    storage=space.probe(ssh,needed["required"])
    print("storage     "+space.display(storage))
    if not storage["ok"]:
        print("ERR space-preflight-"+storage["state"]+"; nothing uploaded")
        return 8
    if verdict != "newer":
        print("ERR not-newer: verified updater will not reinstall or downgrade; nothing uploaded")
        return 3
    if not args.yes:
        print("DRY         re-run with --yes to upload, install and apply")
        return 0

    remote = f"ux0:/VITA-POC/{pkg.stem}-{facts['sha256'][:8]}.vpk"
    stage = time.strftime("%H:%M:%S")
    print(f"[{stage}] upload      {pkg.name} -> {remote} ({facts['bytes']} bytes)")
    rc, out = ssh(f"put {remote} {facts['bytes']} sha256={facts['sha256']}",
                  timeout=args.timeout, stdin_bytes=pkg.read_bytes())
    print(f"[{time.strftime('%H:%M:%S')}] upload      {out or ('rc=' + str(rc))}")
    if rc!=0 or out!=f"OK put path={remote} bytes={facts['bytes']} sha256={facts['sha256']}":
        print("ERR upload-failed; nothing was installed")
        return 4

    rc, out = ssh(f"inspect {remote}")
    if rc!=0 or not out.splitlines() or out.splitlines()[0]!=f"file bytes={facts['bytes']} sha256={facts['sha256']}":
        print("ERR device-hash-mismatch")
        print(out)
        return 5
    print(f"[{time.strftime('%H:%M:%S')}] verify      device sha256 matches")

    rc, out = ssh(f"install {remote} sha256={facts['sha256']}", timeout=args.timeout)
    print(f"[{time.strftime('%H:%M:%S')}] install     {out.splitlines()[-1] if out else 'rc=' + str(rc)}")
    if rc!=0 or not out.splitlines() or re.fullmatch(r"OK install version="+re.escape(facts['app_ver'])+r" title=INAP00018 files=[1-9]\d* bytes=[1-9]\d* payload=\S+ core=queued session=kept",out.splitlines()[-1]) is None:
        print("ERR install-failed")
        print(out)
        return 6

    if args.no_apply:
        print("[%s] queued      no updater launched. For R1, review physically on Vita; check r1-status then issue the physically granted apply-return NONCE from the terminal. Do not run historical exec-based scripts. For attended manual update only: wbctl apply --version %s" % (time.strftime("%H:%M:%S"), facts["app_ver"]))
        return 0

    rc, out = ssh("apply-core", timeout=30)
    print(f"[{time.strftime('%H:%M:%S')}] updater     {out.splitlines()[0] if out else 'connection dropped (expected)'}")
    if not apply_observable(rc,out):
        print("INCONCLUSIVE or refused updater handoff; inspect queue, do not retry automatically");return 7
    state, ver_out = wait_for_version(facts["app_ver"], before.get("run", ""), args.timeout)
    print(f"[{time.strftime('%H:%M:%S')}] result      {state}")
    if ver_out:
        print(ver_out)
    if state != "verified":
        print("hint        wait for SSH LISTENING; respond only if the Vita actually prompts, then run wbctl doctor")
    tl = fetch_timeline()
    if tl:
        print("timeline    " + "\n            ".join(tl[-6:]))
    return 0 if state == "verified" else 7


def cmd_apply(args) -> int:
    """Apply the already queued package: updater + wait for the new version."""
    rc, out = ssh("pending")
    target = args.version
    m=re.fullmatch(r"pending-core: WBQ2 (\d{2}\.\d{2}) [0-9a-f]{64} [1-9]\d*",out)
    if rc==0 and m and (not target or target==m[1]): target=m[1]
    else: target=None
    if not target:
        print(f"ERR no-queue ({out})")
        return 3
    rc,before_raw = ssh("ver")
    before = ver_fields(before_raw)
    if rc!=0 or not before:
        print("ERR no verified source run; queue not applied");return 3
    rc, out = ssh("apply-core", timeout=30)
    print(f"[{time.strftime('%H:%M:%S')}] updater     {out.splitlines()[0] if out else 'connection dropped (expected)'}")
    if not apply_observable(rc,out):
        print("INCONCLUSIVE or refused updater handoff; inspect queue, do not retry automatically");return 7
    state, ver_out = wait_for_version(target, before.get("run", ""), args.timeout)
    print(f"[{time.strftime('%H:%M:%S')}] result      {state}")
    if ver_out:
        print(ver_out)
    if state != "verified":
        print("hint        wait for SSH LISTENING; respond only if the Vita actually prompts")
    return 0 if state == "verified" else 7


def cmd_app_local(args) -> int:
    try:
        with approve_file(Path(args.vpk), args.case) as (facts, source):
            return _app_approved(args, facts, source)
    except Denied as exc:
        print(json.dumps({"status": "DENIED", "reason": str(exc)}))
        return 2


def _app_approved(args, facts, source) -> int:
    title = facts["title_id"]
    if title != TESTAPP_ID and not facts["install_only"]:
        print("ERR device-title-not-supported")
        return 2
    if args.app_cmd == "plan":
        print(json.dumps(facts))
        return 0
    if not args.yes:
        print(json.dumps(facts))
        print("DRY         --yes required; no SSH performed")
        return 0
    # Derive the destination only from approved identity; transmit the inspected bytes.
    remote = f"ux0:/VITA-POC/{title}-{facts['sha256'][:8]}-{os.urandom(6).hex()}.vpk"
    rc, out = ssh(f"put {remote} {facts['bytes']} sha256={facts['sha256']}",
                  timeout=args.timeout, stdin_bytes=source)
    print(f"[{time.strftime('%H:%M:%S')}] upload      {out or 'rc=' + str(rc)}")
    # put/app-install each emits exactly one terminal receipt. Mixed or
    # duplicate records are unconfirmed, even if SSH reports exit 0.
    if rc != 0 or out != f"OK put path={remote} bytes={facts['bytes']} sha256={facts['sha256']}":
        print("ERR upload-unconfirmed; app-install was not sent")
        return 4
    rc, out = ssh(f"app-install {remote}", timeout=args.timeout, progress_total=facts['bytes'])
    print(f"[{time.strftime('%H:%M:%S')}] app-install {out}")
    receipt = (rf"OK app-install title={re.escape(title)} app_ver={re.escape(facts['app_ver'])}"
               r" files=[1-9][0-9]* detail=(?:0|[1-9][0-9]*) session=kept")
    if rc != 0 or re.fullmatch(receipt, out) is None:
        print("ERR app-install-unconfirmed; check installed state before retrying")
        return 5
    return 0


def _job_assert(case, text):
    """Return True/False from the exact TestApp 01.00 assertion; None if not an expected assertion."""
    if case == "fs-smoke":
        if text == "open-write-failed": return False
        m = re.fullmatch(r"write=(-?\d{1,10}) read=(-?\d{1,10}) match=([01])", text)
        if m: return m.groups() == ("64", "64", "1")
    elif case == "compute-smoke":
        m = re.fullmatch(r"fnv1a=0x([0-9A-F]{8}) expected=0x([0-9A-F]{8})", text)
        if m: return m.groups() == ("655C5FFD", "655C5FFD")
    elif case == "power-smoke":
        m = re.fullmatch(r"battery=(-?\d{1,10}) temp_raw=(-?\d{1,10})", text)
        if m:
            pct, raw = map(int,m.groups())
            return 0 <= pct <= 100 and -2000 < raw < 9000
    return None


def _job_fields(raw, job, title, case, build):
    """Identity and semantics before verdict: never write a stale PASS as the canonical result."""
    fields = {}
    raw = raw.replace("\r\n", "\n")
    if len(raw) > 1024 or not raw.isascii() or any(ch != "\n" and not 32 <= ord(ch) <= 126 for ch in raw):
        return {}, "invalid-result-size-or-encoding"
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key in fields or not value or any(ord(c)<32 or ord(c)>126 for c in value):
            return {}, "malformed-or-duplicate-result-field"
        fields[key] = value
    if set(fields) != {"job","title","case","build","assert","result"}:
        return {}, "unexpected-or-missing-result-field"
    for key, expected in (("job",job),("title",title),("case",case),("build",build)):
        if fields[key] != expected:
            return fields, "device-"+key+"-mismatch"
    valid = _job_assert(case, fields["assert"])
    if (fields["result"],valid) not in (("PASS",True),("FAIL",False)):
        return fields, "invalid-or-contradictory-assertion"
    return fields, ""


def cmd_test_run(args) -> int:
    try:
        intended, _ = approve(Path(args.vpk), args.case)
    except Denied as exc:
        print(json.dumps({"status": "DENIED", "reason": str(exc)}))
        return 2
    if intended["title_id"] != TESTAPP_ID:
        print("ERR device-title-not-supported"); return 2
    if not 1 <= args.timeout <= 600:
        print("ERR timeout must be 1..600 seconds"); return 2
    job = time.strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(6).hex()
    expected_build = intended["app_ver"] + "-testapp"
    v = {"job":job,"title":TESTAPP_ID,"case":args.case,"expected_build":expected_build,
         "approved_vpk_sha256":intended["sha256"], "expected_core":CORE_VERSION, "expected_core_build":CORE_BUILD}
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    outfile = JOBS_DIR / (job+".json")
    rawfile = JOBS_DIR / (job+".txt")
    if rawfile.exists() or outfile.exists():
        print("ERR job collision; no device command sent"); return 2
    def finish(result,reason,code):
        v["result"]=result
        v["reason"]=reason
        with outfile.open("x",encoding="utf8") as output:
            json.dump(v,output,indent=2); output.write("\n")
        print("result     ",result,reason)
        print("report     ",outfile)
        return code
    print("job        ",job,flush=True)
    rc, ver = ssh("ver")
    if rc: return finish("INCONCLUSIVE","before-verification-failed",7)
    try: before = checked_ver(ver)[0]
    except CoreError as e: return finish("INCONCLUSIVE",str(e),7)
    v["run_before"]=before
    rc,out=ssh(f"launch {TESTAPP_ID} {args.case} {job}", timeout=30)
    v["launch_rc"]=rc;v["launch_reply"]=out[:512]
    print("launch     ",out[:512],flush=True)
    if rc==78: return finish("INCONCLUSIVE","launch-host-trust-failed",7)
    if any(l.startswith("ERR ") for l in out.splitlines()):
        return finish("REJECTED","device-explicitly-refused-launch",4)
    expected_ack=f"OK launch title={TESTAPP_ID} case={args.case} job={job}"
    # The approved title switch may close SSH before the platform's success ACK.
    # Even then, observe only: never issue another launch for this job.
    if rc==0 and out==expected_ack:
        v["launch_state"]="acknowledged"
    elif rc in (124,255) and not any(l.startswith("OK launch") and l != expected_ack for l in out.splitlines()):
        v["launch_state"]="unknown-after-timeout-or-disconnect"
    else:
        return finish("INCONCLUSIVE","unrecognized-launch-reply",7)

    deadline=time.monotonic()+args.timeout
    back=None
    while time.monotonic()<deadline:
        rc,out=ssh("ver",timeout=max(.05,min(10.,deadline-time.monotonic())))
        if rc==78:return finish("INCONCLUSIVE","returned-host-trust-failed",7)
        if rc==0:
            try: run=checked_ver(out)[0]
            except CoreError as e:return finish("INCONCLUSIVE",str(e),7)
            if run!=before:back=run;break
        time.sleep(max(0.,min(2.,deadline-time.monotonic())))
    if not back:return finish("INCONCLUSIVE","no-new-workbench-run-before-deadline",7)
    v.update(core_after=CORE_VERSION,core_build_after=CORE_BUILD,run_after=back)
    rc,raw=ssh("get ux0:data/INAP00018/testapp/result.txt",timeout=20)
    # Store untrusted decoded raw stdout independently of the typed authoritative verdict.
    with rawfile.open("x",encoding="utf8") as f:f.write(raw)
    v["raw_file"]=rawfile.name;v["get_rc"]=rc
    if rc!=0:return finish("INCONCLUSIVE","result-read-failed",7)
    fields,reason=_job_fields(raw,job,TESTAPP_ID,args.case,expected_build)
    if fields:
        v.update(device_job=fields["job"],device_title=fields["title"],device_case=fields["case"],build=fields["build"],
                 **{"assert":fields["assert"],"device_claimed_result":fields["result"]})
    if reason:return finish("INCONCLUSIVE",reason,7)
    # get and ver use different authenticated connections. Check that result retrieval
    # was bracketed by the same new Workbench process rather than two different runs.
    rc,out=ssh("ver",timeout=10)
    if rc!=0:return finish("INCONCLUSIVE","post-result-verification-failed",7)
    try: after=checked_ver(out)[0]
    except CoreError as e:return finish("INCONCLUSIVE",str(e),7)
    if after!=back:return finish("INCONCLUSIVE","core-changed-during-result-read",7)
    return finish(fields["result"],"device-assertion-verified",0 if fields["result"]=="PASS" else 1)


def cmd_report(args) -> int:
    if not JOBS_DIR.is_dir():
        print("no jobs")
        return 1
    if args.job:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}",args.job):
            print("ERR invalid job id");return 2
        f = JOBS_DIR / (args.job + ".json")
        if not f.is_file():
            print(f"ERR no-such-job {args.job}")
            return 2
        print(f.read_text(encoding="utf-8"))
        return 0
    for f in sorted(JOBS_DIR.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        print(f"{f.stem}  case={d.get('case')}  result={d.get('result')}  build={d.get('build')}")
    return 0


PUT_ROOT = "ux0:/VITA-POC/"
PHOTO_MAX = 8 * 1024 * 1024
PUT_MAX = wb_tree.MAX_BYTES
PHOTO_NAME = re.compile(r"[a-zA-Z0-9_-]{1,95}\.(?:jpe?g|png)", re.ASCII | re.I)
PHOTO_IEND = bytes.fromhex("0000000049454e44ae426082")


def _photo_type(suffix: str) -> str:
    return {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png"}.get(suffix.lower(), "")


def _photo_signature_ok(kind: str, raw: bytes) -> bool:
    # Only a cheap signature/shape check, not a decoder. The native Photos
    # service decides whether the complete media is acceptable.
    if kind == "jpeg":
        return len(raw) >= 5 and raw.startswith(b"\xff\xd8\xff") and raw.endswith(b"\xff\xd9")
    return (kind == "png" and len(raw) >= 45
            and raw.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
            and all(struct.unpack(">II", raw[16:24])) and raw.endswith(PHOTO_IEND))


def _flat_put_path(path: str) -> bool:
    # Never let a path supply another wire argument (notably --install).
    if not path.startswith(PUT_ROOT):
        return False
    name = path[len(PUT_ROOT):]
    return (bool(name) and len(name.encode("utf-8")) <= 100 and not name.endswith(".")
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in ":/\\"
                        for c in name))


def cmd_put(args) -> int:
    local = Path(args.local)
    image = getattr(args, "image", False)
    if not image:
        return _cmd_file_put(args, local)
    limit = PHOTO_MAX if image else PUT_MAX
    try:
        if not local.is_file():
            raise ValueError("not a regular file")
        with local.open("rb") as f:
            n = os.fstat(f.fileno()).st_size
            if not 0 < n <= limit:
                raise ValueError(f"expected 1..{limit} bytes")
            raw = f.read(n + 1)
            if len(raw) != n:
                raise ValueError("input size changed during read")
    except (ValueError, OSError) as exc:
        print(f"ERR local-file {exc}")
        return 2
    sha = hashlib.sha256(raw).hexdigest()
    name = local.name
    kind = _photo_type(local.suffix)
    if image:
        if not _photo_signature_ok(kind, raw):
            print("ERR image-format: use a JPEG (.jpg/.jpeg) or PNG (.png) with matching content")
            return 2
        if not PHOTO_NAME.fullmatch(name):
            name = f"photo-{sha}{local.suffix.lower()}"
    remote = args.remote if args.remote is not None else PUT_ROOT + name
    if not _flat_put_path(remote) or (image and (
            not PHOTO_NAME.fullmatch(remote[len(PUT_ROOT):]) or
            _photo_type(Path(remote).suffix) != kind)):
        print(f"ERR invalid destination: use one safe filename under {PUT_ROOT}")
        return 2

    upload = True
    if image:
        rc, out = ssh("help", timeout=args.timeout)
        if (rc != 0 or any(line.startswith("ERR ") for line in out.splitlines())
                or not (re.search(r"(?m)^ +photo-export[ \t]+<", out) or re.search(r"(?m)^Workbench commands include [^\n]*\bphoto-export\b",out) or re.search(r"(?m)^Workbench: [^\n]*\bphoto-export\b",out))):
            print("ERR photo-export capability not confirmed; nothing uploaded or exported")
            return 3
        rc, out = ssh(f"ext stat {remote}", timeout=args.timeout)
        if (rc, out) == (0, f"F {remote} {n}"):
            # Same size is not identity. The device hashes the existing bytes
            # and must match sha before calling the native photo export API.
            upload = False
            print(f"Staged file exists; verifying SHA-256 before export: {remote}")
        elif rc not in (0,1) or out != "ERR not-found":
            print(f"ERR stage-check: {out or ('rc=' + str(rc))}; no overwrite or export")
            return 4
    if upload:
        rc, out = ssh(f"put {remote} {n} sha256={sha}", timeout=args.timeout, stdin_bytes=raw)
        print(out or f"rc={rc}")
        if (rc, out) != (0, f"OK put path={remote} bytes={n} sha256={sha}"):
            print("ERR upload not confirmed; no export requested")
            return 4
    if not image:
        return 0
    rc, out = ssh(f"photo-export {remote} {sha}", timeout=args.timeout)
    if (rc, out) == (0, f"OK photo-export bytes={n} sha256={sha}"):
        print(out)
        return 0
    if rc in (0, 1, 125) and out.startswith("ERR ") and len(out.splitlines()) == 1:
        print(out)
        print(f"Photo export not confirmed; staged file retained at {remote}")
        return 5
    # A lost or contradictory response after dispatch is NOT evidence of
    # failure. Retrying automatically could create a duplicate Photos entry.
    print(f"INCONCLUSIVE photo-export (rc={rc}): check Photos before retry; staged file: {remote}")
    return 6


def _cmd_file_put(args, local) -> int:
    remote=args.remote if args.remote is not None else PUT_ROOT+local.name
    if not _flat_put_path(remote):
        print(f"ERR invalid destination: use one safe filename under {PUT_ROOT}")
        return 2
    try:
        with wb_tree.file_snapshot(local, PUT_MAX) as source:
            rc,out=ssh(f"put {remote} {source.size} sha256={source.sha256}",
                       timeout=args.timeout,stdin_bytes=source)
            print(out or f"rc={rc}")
            if (rc,out)!=(0,f"OK put path={remote} bytes={source.size} sha256={source.sha256}"):
                print("ERR upload not confirmed; do not automatically retry")
                return 4
            return 0
    except (OSError,ValueError) as exc:
        print(f"ERR local-file {exc}")
        return 2


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="wbctl", description="Vita Workbench control (5090)")
    ap.add_argument("--json", action="store_true", help="machine readable output where supported")
    sub = ap.add_subparsers(dest="cmd", required=True)
    import crash_cli
    crash_cli.register(sub)
    import review_digest
    review_digest.register(sub)
    import stage_review
    stage_review.register(sub)
    import wake_preflight
    wake_preflight.register(sub)
    sub.add_parser("open", help="read-only WB running-status advisory; no wake dispatch in this release")

    sub.add_parser("doctor", help="device identity, versions, queue, timeline tail")
    sub.add_parser("ver", help="raw version line")
    import status_client
    status_client.register(sub)
    sub.add_parser("deny-check", help="confirm a malformed read-only terminal command is rejected (not an SSH exec test)")
    sub.add_parser("timeline", help="upgrade timeline from the device")

    p_plan = sub.add_parser("plan", help="local package analysis + verdict against the device")
    p_plan.add_argument("vpk")
    p_plan.add_argument("--reserve-bytes",type=int,default=0,help="additional required free space; never lowers the built-in margin")

    p_upd = sub.add_parser("update", help="upload, install and apply a newer workbench package")
    p_upd.add_argument("vpk")
    p_upd.add_argument("--reserve-bytes",type=int,default=0,help="additional required free space; never lowers the built-in margin")
    p_upd.add_argument("--yes", action="store_true")
    p_upd.add_argument("--force", action="store_true")
    p_upd.add_argument("--no-apply", action="store_true")
    p_upd.add_argument("--timeout", type=float, default=240.0)

    p_app = sub.add_parser("app", help="owner-approved app installation (not an implicit launch)")
    app_sub = p_app.add_subparsers(dest="app_cmd", required=True)
    p_app_plan = app_sub.add_parser("plan", help="offline title/version/hash/case registry preflight")
    p_app_plan.add_argument("vpk")
    p_app_plan.add_argument("--case", help="also validate a registered test case")
    p_app_i = app_sub.add_parser("install", help="stage and promote an approved package; never launch it")
    p_app_i.add_argument("vpk")
    p_app_i.add_argument("--case", help="also validate a registered test case")
    p_app_i.add_argument("--yes", action="store_true")
    p_app_i.add_argument("--timeout", type=float, default=7200.0,
                         help="seconds per upload/install operation (default: 7200; large apps need time)")

    p_test = sub.add_parser("test", help="run a device case through the approved test app")
    test_sub = p_test.add_subparsers(dest="test_cmd", required=True)
    p_test_r = test_sub.add_parser("run", help="run one case and collect its result")
    p_test_r.add_argument("case")
    p_test_r.add_argument("--vpk", required=True, help="approved intended local VPK; no installed-byte attestation")
    p_test_r.add_argument("--timeout", type=float, default=120.0)

    p_report = sub.add_parser("report", help="list or print saved job reports")
    p_report.add_argument("job", nargs="?")

    p_apply = sub.add_parser("apply", help="apply the queued package and wait for the new core")
    p_apply.add_argument("--version", default="")
    p_apply.add_argument("--timeout", type=float, default=240.0)

    p_put = sub.add_parser("put", help="upload one file to ux0:/VITA-POC")
    p_put.add_argument("local")
    p_put.add_argument("remote", nargs="?")
    p_put.add_argument("--image", action="store_true",
                       help="also import a JPEG/PNG (up to 8 MiB) into Vita Photos; default: upload only")
    p_put.add_argument("--timeout", type=float, default=240.0)

    args = ap.parse_args(argv)
    if args.cmd == "stage-review":
        return stage_review.command(args,(HOST,str(PORT),USER))
    if args.cmd == "review-digest":
        return review_digest.command(args,(HOST,str(PORT),USER))
    if args.cmd == "diag":
        return crash_cli.command(args,(HOST,str(PORT),USER))
    if args.cmd == "status":
        return status_client.command(args,(HOST,str(PORT),USER))
    if args.cmd == "wake-preflight":
        return wake_preflight.command(args,(HOST,str(PORT),USER))
    if args.cmd == "open":
        rc,report=wake_preflight.open_status((HOST,str(PORT),USER))
        print(json.dumps(report,ensure_ascii=True) if args.json else report["status"])
        return rc
    if args.cmd == "app":
        return cmd_app_local(args)
    if args.cmd == "test":
        return cmd_test_run(args)
    table = {
        "doctor": cmd_doctor,
        "ver": cmd_ver,
        "deny-check": cmd_deny_check,
        "timeline": cmd_timeline,
        "plan": cmd_plan,
        "apply": cmd_apply,
        "report": cmd_report,
        "update": cmd_update,
        "put": cmd_put,
    }
    return table[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
