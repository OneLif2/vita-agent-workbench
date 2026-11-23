"""Actual main APPLY_RETURN case + actual R1/focus code, deterministic SDK stubs.
Offline only. --source/--expect permit baseline and rollback without release writes.
"""
from pathlib import Path
import argparse,importlib.util,subprocess,tempfile,sys
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
spec=importlib.util.spec_from_file_location("signed_focus_materializer",ROOT/"tests/signed_focus/run.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def materialize(d,source,return_header=None):
    m.materialize(d)
    f=d/"fixture.c";c=f.read_text(encoding="utf-8")
    c=c[:c.index("static void ready_to_apply(void)")]
    old="uint64_t rtc_last;} a;"
    assert c.count(old)==1
    c=c.replace(old,"uint64_t rtc_last,guard_grace;bool updater_accepted;} a;")
    c=c.replace("static bool fail_save,","static bool inject_active;static void operation(int at);\nstatic bool late_power,late_skew,late_cancel_fail;\nstatic bool fail_save,")
    read="obj*f=&files[slot(p)];if("
    assert c.count(read)==1
    c=c.replace(read,'if(inject_active && !strcmp(p,R1_LOCAL_PATH))operation(6);\n    '+read)
    save="memcpy(f->data,b,n);f->n=n;f->exists=true;return WB_OK;}"
    inject="""memcpy(f->data,b,n);f->n=n;f->exists=true;
    if(i==0 && n==sizeof(r1_local) && ((const r1_local*)b)->phase==R1_DISPATCHED){
        if(late_power)++a.power_calls;
        if(late_skew)wall+=200001u;
        if(late_cancel_fail)fail_save=true;
    }
    return WB_OK;}"""
    assert c.count(save)==1;c=c.replace(save,inject)
    body=source.read_text(encoding="utf-8")
    begin="        case WB_CMD_APPLY_RETURN:"
    end=("        case WB_CMD_TERM_APP_RUNNING:" if "        case WB_CMD_TERM_APP_RUNNING:" in body
         else "        case WB_CMD_BYE:")
    assert body.count(begin)==body.count(end)==1
    branch=body[body.index(begin):body.index(end,body.index(begin))]
    assert branch.rstrip().endswith("}") and "case WB_CMD_APPLY_CORE:" in branch
    assert "wb_app_running_command" not in branch and "wb_probe_command" not in branch
    (d/"handoff.inc").write_text(branch,encoding="utf-8")
    f.write_text(c+(D/"native.c.in").read_text(encoding="utf-8"),encoding="utf-8")
    if return_header is not None:
        (d/"wb_return_vita.h").write_bytes(return_header.read_bytes())

def main():
    a=argparse.ArgumentParser();a.add_argument("input",nargs="?",default="all",choices=["all","intergate-2s","teststat-2s","private-read-2s"])
    a.add_argument("--source",type=Path,default=ROOT/"source/vita_ssh_status.c")
    a.add_argument("--return-header",type=Path)
    a.add_argument("--expect",choices=["pass","refuse"],default="pass");a=a.parse_args()
    with tempfile.TemporaryDirectory(prefix="wb-full-handoff-") as tmp:
        d=Path(tmp);materialize(d,a.source,a.return_header);exe=m.build(d)
        args=[str(exe),a.input,a.expect]
        o=subprocess.run(args,cwd=d,capture_output=True,text=True)
        print(o.stdout,end="");print(o.stderr,end="",file=sys.stderr)
        if o.returncode:return o.returncode
        assert o.stderr==""
        return 0
if __name__=="__main__":raise SystemExit(main())
