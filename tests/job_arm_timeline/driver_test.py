"""Offline acceptance-driver regressions, including lost ACK and stale PASS. No SSH."""
import contextlib,io,json,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"hardware"))
import arm_timeline_0132 as a
class Sim:
    old="0000000000000001"; new="0000000000000002"
    def __init__(self):
        self.job="";self.launched=0;self.bad_result=False;self.manual=False;self.no_boot=False;self.reject_s4=False;self.commands=[];self.orphan=False
    def ssh(self,cmd,*,stdin_bytes=None,timeout=0):
        self.commands.append(cmd)
        run=self.new if self.launched else self.old
        if cmd=="ver":return 0,f"wb version=01.32 build={a.BUILD} abi=3 proto=wb10 run={run} payload=none uptime_ms=1"
        if cmd=="timeline":return 0,"timeline empty" if self.no_boot else f"stage=boot ver=01.32 run={run} ms=0"
        if cmd=="timeline selftest":return (1,"ERR memory-only S4=7/8 C2=4/4\nERR bad-state") if self.reject_s4 else (0,"OK memory-only S4=8/8 C2=4/4")
        if cmd.startswith("df "):return 0,"df volume=ux0: total=20000000 available=10000000 required="+cmd.split()[-1]
        if cmd.startswith("put "):
            _,p,n,h=cmd.split();assert a.hashlib.sha256(stdin_bytes).hexdigest()==a.SHA
            return 0,f"OK put path={p} bytes={n} {h}"
        if cmd.startswith("app-install "):return 0,"OK app-install title=INAP00020 app_ver=01.01 files=2 detail=0 session=kept"
        if cmd.startswith("launch "):self.job=cmd.split()[-1];self.launched+=1;return 255,"Connection closed by remote host"
        if cmd.endswith("/result.txt"):
            job="stale" if self.bad_result else self.job
            return 0,f"job={job}\ntitle=INAP00020\nbuild=01.01-testapp\ncase=fs-smoke\nassert=write=64 read=64 match=1\nresult=PASS"
        if cmd.endswith("/run.log"):
            return (0,"manual PIN") if self.manual else (0,f"run={run} elapsed_ms=1300 AUTOARM JOB OK job={self.job}")
        raise Exception("unexpected command "+cmd)
def expect_error(fn,*args):
    try:fn(*args)
    except (RuntimeError,FileExistsError):return
    raise AssertionError("false acceptance")
with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
    d=Path(temp);s=Sim(); a.w.ssh=s.ssh; a.pin=lambda:"same-public-pinfile-hash"
    s.no_boot=True; expect_error(a.check,d)
    row=a.read(sorted(d.glob("check-*.json"))[-1]);assert row["C2"]=="INCONCLUSIVE" and row["S4_fixture"]=="PASS"
    s.no_boot=False;s.reject_s4=True;expect_error(a.check,d)
    row=a.read(sorted(d.glob("check-*.json"))[-1]);assert row["C2"]=="PASS" and row["S4_fixture"]=="INCONCLUSIVE"
    s.reject_s4=False;a.check(d);a.launch(d);assert s.launched==1;expect_error(a.launch,d)
    s.bad_result=True;expect_error(a.collect,d,3)
    s.bad_result=False;s.manual=True;expect_error(a.collect,d,3)
    s.manual=False;a.collect(d,3);assert s.launched==1
    results=[a.read(f)["S4"] for f in sorted(d.glob("collect-*.json"))];assert results==["INCONCLUSIVE","INCONCLUSIVE","PASS"],results
print("PASS offline device driver: independent C2/S4 status; launch once despite ambiguous SSH; stale result/manual arm rejected; correct job + autoarm accepted.")

