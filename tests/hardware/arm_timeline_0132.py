"""01.32 S4/C2 device acceptance. No re-pair; only launch phase mutates the Vita.
check/collect read only. Use the same evidence directory; never repeat a launch.
"""
import argparse,hashlib,json,os,re,secrets,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import wbctl as w, pinned_check as pc, space_budget as space
from app_registry import approve

SHA="a4e817a78dc550f7c2fb09faeb0fdb96cce937d8279818d0d715fd9d4cd11255"
FP="HOST_SHA256"
BUILD="01.32-live-wbq2"; TITLE="INAP00020"; CASE="fs-smoke"; P=ROOT/"build/testapp.vpk"
def require(ok,msg):
    if not ok:raise RuntimeError(msg)
def now():return datetime.now(timezone.utc).isoformat()
def name():return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
def read(p):return json.loads(p.read_text(encoding="utf8"))
def save(p,**row):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("x",encoding="utf8") as f:
        json.dump({"utc":now(),**row},f,ensure_ascii=False,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def pin():
    require((w.HOST,int(w.PORT),w.USER)==("192.0.2.10",2222,"pi"),"unapproved endpoint")
    public=read(ROOT/"evidence/physical-owner.json")["host_fingerprint"]
    path,fp=pc.canonical_saved(pc.pin_path(w.HOST,int(w.PORT)),w.HOST,int(w.PORT))
    require(fp==FP==public,"unexpected public host fingerprint; stop, do not repair")
    return hashlib.sha256(path.read_bytes()).hexdigest()
def rpc(d,cmd,*,data=None,timeout=20):
    # wbctl.ssh uses strict checking against owner's per-endpoint pairing.
    rc,out=w.ssh(cmd,stdin_bytes=data,timeout=timeout)
    with (d/"commands.jsonl").open("a",encoding="utf8") as f:
        f.write(json.dumps({"utc":now(),"command":cmd,"rc":rc,"combined_output":out})+"\n")
    print(f"[{rc}] {cmd}: {out[:180]}",flush=True)
    if rc==78:raise RuntimeError("trust configuration or host key rejected")
    return rc,out
def ver(d,wait=False):
    rc,o=rpc(d,"ver",timeout=8)
    if rc!=0 and wait and rc in (124,255):return None
    require(rc==0,"no confirmed version")
    m=re.fullmatch(r"wb version=01\.32 build=01\.32-live-wbq2 abi=3 proto=wb10 run=([0-9A-F]{16}) payload=\S+ uptime_ms=\d+",o)
    require(m,"wrong core/version; stop");return m[1]
def check(d):
    pin_h=pin();run=ver(d)
    c,o=rpc(d,"timeline selftest")
    m=re.fullmatch(r"(OK|ERR) memory-only S4=(\d+)/8 C2=(\d+)/4(?:\nERR [^\n]+)?",o)
    tr,tl=rpc(d,"timeline")
    boot=any(re.fullmatch("stage=boot ver=01\\.32 run="+run+r" ms=\d+",line) for line in tl.splitlines())
    same=ver(d)==run and pin()==pin_h
    valid=c in (0,1) and m is not None and same
    s4=bool(valid and m[2]=="8");c2=bool(valid and m[3]=="4" and tr==0 and boot)
    save(d/("check-"+name()+".json"),run=run,build=BUILD,pin_file_sha256=pin_h,
         C2=("PASS" if c2 else "INCONCLUSIVE"),S4_fixture=("PASS" if s4 else "INCONCLUSIVE"),
         S4_end_to_end="PENDING",matches_current_boot=boot,device_memory_only=o,
         limits="C2: real synced generation containing boot; failure injection uses isolated memory, no power loss.")
    require(s4 and c2,"S4/C2 incomplete; see independent statuses")
def freeze():
    facts,raw=approve(P,CASE)
    require((facts["title_id"],facts["app_ver"],facts["case"],facts["sha256"])==(TITLE,"01.01",CASE,SHA)
        and hashlib.sha256(raw).hexdigest()==SHA,"local TestApp identity/digest refused")
    return raw
def launch(d):
    raw=freeze()
    pin_h=pin();run=ver(d)
    checks=sorted(d.glob("check-*.json"))
    require(any(x["run"]==run and x["pin_file_sha256"]==pin_h and x["S4_fixture"]=="PASS" for x in map(read,checks)),
            "run check on the current core first")
    job="s4-"+name()+"-"+secrets.token_hex(4);remote="ux0:/VITA-POC/test0132-"+secrets.token_hex(8)+".vpk"
    # Exclusive create BEFORE any mutation; even after transport loss never redo launch.
    path=d/"launch";save(path/"intent.json",job=job,run=run,case=CASE,title=TITLE,app_build="01.01-testapp",build=BUILD,
                         hash=SHA,host_key=FP,pin_file_sha256=pin_h,remote=remote)
    budget=space.requirement(w.vpk_facts(P)); sp=space.probe(lambda cmd:rpc(d,cmd),budget["required"])
    save(path/"budget.json",budget=budget,observation=sp);require(sp["ok"],"df refused before upload")
    rc,out=rpc(d,f"put {remote} {len(raw)} sha256={SHA}",data=raw,timeout=90)
    require(rc==0 and f"OK put path={remote} bytes={len(raw)} sha256={SHA}" in out.splitlines(),"upload unconfirmed")
    rc,out=rpc(d,"app-install "+remote,timeout=90)
    require(rc==0 and re.fullmatch(r"OK app-install title=INAP00020 app_ver=01\.01 files=[1-9]\d* detail=\d+ session=kept",out),
            "Vita did not accept the exact companion package")
    require(ver(d)==run and pin()==pin_h,"unexpected app-install restart or pairing change")
    save(path/"issued.json",job=job,run=run,command=f"launch {TITLE} {CASE} {job}")
    rc,out=rpc(d,f"launch {TITLE} {CASE} {job}",timeout=30)
    ack=(rc==0 and out==f"OK launch title={TITLE} case={CASE} job={job}")
    save(path/"ack.json",rc=rc,ack=ack,output=out)
    require(ack or (rc in (124,255) and "ERR " not in out),"launch refused; do not retry")
    print("Single launch sent. Use only collect on this record path.",flush=True)
def collect(d,timeout):
    path=d/"launch";b=read(path/"intent.json"); issued=read(path/"issued.json"); job=b["job"]
    require(issued["job"]==job and issued["run"]==b["run"] and b["host_key"]==FP and b["hash"]==SHA
         and pin()==b["pin_file_sha256"],"mismatched launch record or pairing")
    ackpath=path/"ack.json"
    if ackpath.exists():
        ack=read(ackpath);require(ack["ack"] or (ack["rc"] in (124,255) and "ERR " not in ack["output"]),"launch was denied")
    deadline=time.monotonic()+timeout;run=None
    while time.monotonic()<deadline:
        run=ver(d,wait=True)
        if run and run!=b["run"]:break
        time.sleep(3)
    else: raise RuntimeError("INCONCLUSIVE: no new run; only retry collect")
    rc,raw=rpc(d,"get ux0:data/INAP00018/testapp/result.txt")
    lr,logs=rpc(d,"get ux0:data/INAP00018/run.log")
    same=ver(d)==run and pin()==b["pin_file_sha256"]
    expected={"job":job,"title":TITLE,"case":CASE,"build":"01.01-testapp","result":"PASS","assert":"write=64 read=64 match=1"}
    pairs=[line.partition("=") for line in raw.splitlines()]; fields={k:v for k,_,v in pairs}
    jobpass=rc==0 and all(e=="=" for _,e,_ in pairs) and len(pairs)==len(fields) and fields==expected
    auto=lr==0 and any(re.fullmatch(r"run="+run+r" elapsed_ms=\d+ AUTOARM JOB OK job="+re.escape(job),l) for l in logs.splitlines())
    passed=same and auto and jobpass
    save(d/("collect-"+name()+".json"),S4=("PASS" if passed else "INCONCLUSIVE"),original_run=b["run"],run=run,
         job=job,job_result_matches=jobpass,autoarm_owner_record_matches=auto,pin_run_stable=same,received=fields)
    require(passed,"INCONCLUSIVE: need new stable run, exact app result AND on-device autoarm entry")
    print(f"S4 PASS job={job} run={b['run']}->{run}, with automatic return marker receipt.",flush=True)
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("phase",choices=["check","launch","collect"])
    ap.add_argument("--records",type=Path,required=True);ap.add_argument("--timeout",type=int,default=100)
    args=ap.parse_args();d=args.records.resolve();require(1<=args.timeout<=600,"timeout must be 1..600 seconds")
    d.mkdir(parents=True,exist_ok=True)
    if args.phase=="check":check(d)
    elif args.phase=="launch":launch(d)
    else:collect(d,args.timeout)
if __name__=="__main__":
    try: main()
    except (OSError,ValueError,KeyError,RuntimeError) as exc:
        print("STOP:",exc,file=sys.stderr);sys.exit(2)

