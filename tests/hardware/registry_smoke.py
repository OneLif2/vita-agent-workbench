"""Fixed owner-approved device acceptance. Default 'fixtures' is offline.

'exercise' issues 3 policy-denied installs, 1 approved install, 2 denied launches,
then exactly 1 positive fs-smoke job. 'collect' is read-only; it never relaunches
and cannot re-pair. Use only the owner's already paired 01.31 Workbench.
"""
from __future__ import annotations
import argparse, datetime, hashlib, io, json, os, re, sys, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import wbctl as w
import pinned_check as pair
from app_registry import approve, read_identity

TITLE="INAP00020"; ALT="INAP00998"; CASE="fs-smoke"; VERSION="01.31"; BUILD="01.31-live-registry1"
VPK=ROOT/"build/testapp.vpk"; SIGNED_OFF="f2609d1c89e88fd4b250019a0ca0160b97b2ad8b0028576310effac8fc990905"
JOBPATH="ux0:data/INAP00018/job.txt"; RESULTPATH="ux0:data/INAP00018/testapp/result.txt"
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b): return hashlib.sha256(b).hexdigest()
def require(ok,reason):
    if not ok: raise RuntimeError(reason)
def save(p,data):
    with p.open("x",encoding="utf8") as f:json.dump(data,f,ensure_ascii=False,indent=2);f.write("\n")

def fixtures():
    rows,approved=approve(VPK,CASE)
    require(rows["title_id"]==TITLE and rows["app_ver"]=="01.00" and sha(approved)==SIGNED_OFF,"approved input drift")
    with zipfile.ZipFile(io.BytesIO(approved)) as z: sfo=z.read("sce_sys/param.sfo")
    def metadata(old,new):
        old=old.encode()+b"\0"; new=new.encode()+b"\0"
        require(len(old)==len(new) and sfo.count(old)==1,"ambiguous metadata field")
        out=io.BytesIO()
        with zipfile.ZipFile(out,"w") as z:
            entry=zipfile.ZipInfo("sce_sys/param.sfo",(2000,1,1,0,0,0));z.writestr(entry,sfo.replace(old,new))
        return out.getvalue()
    # Metadata-only samples have NO executable. Comment-only variant keeps every member identical.
    other=metadata(TITLE,ALT); wrong_ver=metadata("01.00","01.99")
    zbuf=io.BytesIO(approved)
    with zipfile.ZipFile(zbuf,"a") as z:z.comment=b"WB31 device policy smoke: packaging metadata only"
    wrong_hash=zbuf.getvalue()
    with zipfile.ZipFile(io.BytesIO(approved)) as a, zipfile.ZipFile(io.BytesIO(wrong_hash)) as b:
        require(a.namelist()==b.namelist() and all(a.read(n)==b.read(n) for n in a.namelist()),"variant changed members")
    cases=[("install-title",other,ALT,"01.00","ERR registry-title"),
           ("install-version",wrong_ver,TITLE,"01.99","ERR registry-version"),
           ("install-sha",wrong_hash,TITLE,"01.00","ERR registry-sha256")]
    for name,raw,t,v,reason in cases:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            meta=w.parse_sfo(z.read("sce_sys/param.sfo"))
            if name!="install-sha":require(z.namelist()==["sce_sys/param.sfo"],"metadata sample must not be executable")
        require((meta["TITLE_ID"],meta["APP_VER"])==(t,v) and sha(raw)!=SIGNED_OFF,"invalid "+name)
    return approved,cases

def record(d,j):
    with (d/"commands.jsonl").open("a",encoding="utf8") as f:f.write(json.dumps({"utc":now(),**j},ensure_ascii=False)+"\n")
def remote(d,cmd,*,data=None,timeout=18):
    rc,out=w.ssh(cmd,stdin_bytes=data,timeout=timeout)
    record(d,dict(command=cmd,rc=rc,combined_output=out,source="5090 strict OpenSSH; Vita Workbench exec"))
    print(f"[{rc}] {cmd}: {out}",flush=True);return rc,out
def device(d):
    rc,out=remote(d,"ver",timeout=8)
    if rc==78: raise RuntimeError("host verification failed; no re-pair")
    if rc!=0:return None
    m=re.fullmatch(r"wb version=(\S+) build=(\S+) abi=3 proto=wb10 run=([0-9A-F]{16}) payload=(\S+) uptime_ms=\d+",out)
    require(m and (m[1],m[2])==(VERSION,BUILD),"unexpected device build, do not test")
    return m[3]
def stored(d,filename):
    rc,out=remote(d,"get "+filename)
    if rc==0:
        require("ERR " not in out,"unexpected read error");return {"present":True,"text":out}
    require("ERR not-found" in out.splitlines(),"no valid file observation")
    return {"present":False}
def upload(d,name,raw):
    target=f"ux0:/VITA-POC/reg31-{name}-{os.urandom(5).hex()}.vpk";h=sha(raw)
    rc,out=remote(d,f"put {target} {len(raw)} sha256={h}",data=raw,timeout=90)
    require(rc==0 and f"OK put path={target} bytes={len(raw)} sha256={h}" in out.splitlines(),"upload receipt mismatch")
    return target
def denial(d,label,command,expect):
    rc,out=remote(d,command);require(0<rc<125 and out.splitlines()[:1]==[expect],"missing Vita denial for "+label)
    return dict(test=label,expected=expect,actual=out.splitlines()[0],rc=rc,verdict="PASS")
def pinned():
    require(w.HOST=="192.0.2.10" and int(w.PORT)==2222 and w.USER=="pi","not signed-off endpoint")
    check=ROOT/"evidence/physical-owner.json"
    approved=json.loads(check.read_text(encoding="utf8"))
    p,fp=pair.canonical_saved(pair.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))
    require(fp==approved["host_fingerprint"],"saved pin differs from known owner; stop")
    return fp,sha(p.read_bytes())
def exercise(d):
    require(not d.exists(),"exercise requires a fresh evidence path; use collect to resume")
    approved,cases=fixtures(); fp,pindigest=pinned();d.mkdir(parents=True)
    run=device(d);require(run,"device not available")
    before=[stored(d,path) for path in (JOBPATH,RESULTPATH)];tests=[]
    for name,raw,_,_,expected in cases:
        target=upload(d,name,raw)
        tests.append(denial(d,name,"app-install "+target,expected))
    # Positive installation must be on the very same core that sent the 3 denials.
    require(device(d)==run,"unexpected restart before approved install")
    target=upload(d,"approved",approved);rc,out=remote(d,"app-install "+target,timeout=90)
    receipt=rf"OK app-install title={TITLE} app_ver=01\.00 files=[1-9]\d* detail=\d+ session=kept"
    require(rc==0 and any(re.fullmatch(receipt,line) for line in out.splitlines()),"approved TestApp install unconfirmed")
    tests.append(dict(test="install-approved",verdict="PASS",actual=out,rc=rc,vpk_sha256=SIGNED_OFF))
    jid="reg31-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")+"-"+os.urandom(4).hex()
    tests.append(denial(d,"launch-title",f"launch {ALT} {CASE} {jid}-nt","ERR registry-title"))
    tests.append(denial(d,"launch-case",f"launch {TITLE} registry-deny {jid}-nc","ERR registry-case"))
    require(device(d)==run and [stored(d,path) for path in (JOBPATH,RESULTPATH)]==before,
            "negative operations changed Workbench run/job/result")
    save(d/"prelaunch.json",dict(utc=now(),run=run,job=jid,build=BUILD,host_key=fp,pin_file_sha256=pindigest,
         registry_sha256=sha((ROOT/"tools/apps.txt").read_bytes()),previous_job_and_result=before,tests=tests))
    rc,out=remote(d,f"launch {TITLE} {CASE} {jid}",timeout=30)
    ready=(f"OK launch title={TITLE} case={CASE} job={jid}" in out.splitlines())
    save(d/"launch.json",dict(utc=now(),rc=rc,reply=out,ack=ready))
    require((rc==0 and ready) or (rc in (124,255) and "ERR " not in out),
            "positive platform launch denied; do not relaunch automatically")
    print("AWAITING RETURN: TestApp owns next result; launch ACK alone is not PASS.",flush=True)
def collect(d,timeout):
    b=json.loads((d/"prelaunch.json").read_text(encoding="utf8"));prev=b["run"];job=b["job"]
    require(pinned()==(b["host_key"],b["pin_file_sha256"]),"pairing changed during test"); deadline=time.monotonic()+timeout
    while True:
        run=device(d)
        if run and run!=prev:break
        if time.monotonic()>=deadline:raise RuntimeError("INCONCLUSIVE: no new Workbench run yet; collect is safe to repeat")
        time.sleep(5)
    rc,raw=remote(d,"get "+RESULTPATH);require(rc==0,"no result")
    lines=[ln.partition("=") for ln in raw.splitlines()];f={k:v for k,_,v in lines}
    require(len(f)==len(lines) and all(s=="=" for _,s,_ in lines),"bad result file")
    require((f.get("job"),f.get("title"),f.get("case"),f.get("build"))==(job,TITLE,CASE,"01.00-testapp"),
            "INCONCLUSIVE: stale or wrong App result")
    require(f.get("result")=="PASS" and f.get("assert")=="write=64 read=64 match=1","TestApp did not pass its fs assertion")
    require(pinned()==(b["host_key"],b["pin_file_sha256"]),"pin changed")
    tests=b["tests"]+[dict(test="launch-approved-fs-smoke",verdict="PASS",actual=f)]
    result=dict(utc=now(),result="PASS",build=BUILD,original_run=prev,returned_run=run,job=job,
                host_key_unchanged=True,negative_job_result_unchanged=True,tests=tests)
    save(d/"RESULT.json",result);print(json.dumps(result,ensure_ascii=False),flush=True)
if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("phase",choices=["fixtures","exercise","collect"]);ap.add_argument("--records",type=Path)
    ap.add_argument("--timeout",type=int,default=90);a=ap.parse_args()
    try:
        if a.phase=="fixtures":
            pos,cs=fixtures();print("approved",len(pos),sha(pos))
            for k,v,t,av,reason in cs:print(k,t,av,len(v),sha(v),reason)
        elif not a.records:ap.error("--records required for a device operation")
        elif a.phase=="exercise":exercise(a.records)
        else:collect(a.records,a.timeout)
    except (ValueError,OSError,RuntimeError,KeyError) as ex:
        print("STOP:",ex,file=sys.stderr);sys.exit(2)
