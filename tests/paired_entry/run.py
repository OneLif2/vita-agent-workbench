"""Actual startup branch: an existing paired listener is not a staged-update grant.
Host SDK stubs only; never connects to Vita. --source supports baseline/rollback.
"""
from pathlib import Path
import argparse,ast,subprocess,tempfile,shutil
here=Path(__file__).resolve().parent
root=here.parents[1]
ap=argparse.ArgumentParser()
ap.add_argument("input",nargs="?",default="pending-paired",choices=["pending-paired"])
ap.add_argument("--source",type=Path,default=root/"source/vita_ssh_status.c")
ap.add_argument("--expect",choices=["square","listener"],default="listener")
a=ap.parse_args()
text=a.source.read_text(encoding="utf-8")
begin="    bool owner_confirmed = false;";end="    wb_strcpy(a.pin, sizeof a.pin, g_ssh.host_pin);"
assert text.count(begin)==text.count(end)==1
branch=text[text.index(begin):text.index(end,text.index(begin))]
module=ast.parse((root/"tests/dispatch/startup_owner.py").read_text(encoding="utf-8"))
fixture=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="fixture" for t in n.targets))
fixture=fixture[:fixture.index("int main(void)")]
fixture=fixture.replace("static bool quick_write", "static inline bool quick_write")
if "bool quick_write(" not in fixture:
    fixture=fixture.replace("static int qr,quick_ok", "static inline bool quick_write(unsigned char val){return val==Q_REMEMBER;}\nstatic int qr,quick_ok")
fixture+=r'''
int main(void){
    memset(ret.host_pin,'A',64);memcpy(g_ssh.host_pin,ret.host_pin,65);
    qr=WB_Q_LOCAL;complete=1;square_ok=0;approval=0;allowed=-1;
    const char *why=route();
    printf("pending-paired state=%s square_asked=%d pin_asked=%d prepares=%d allow_enroll=%d reason=%s\n",
        why?"blocked":"listener",square_asked,asked,prepares,allowed,why?why:"none");
    return 0;
}
'''
fixture=fixture.replace("ACTUAL_BRANCH",branch)
with tempfile.TemporaryDirectory(prefix="wb-paired-entry-") as d:
    d=Path(d);c=d/"fixture.c";exe=d/"fixture.exe"
    c.write_text(fixture,encoding="utf-8")
    subprocess.run([shutil.which("gcc") or "gcc","-std=c11","-Wall","-Wextra","-Werror",str(c),"-o",str(exe)],check=True)
    p=subprocess.run([str(exe)],capture_output=True,text=True,check=True)
    expected=("pending-paired state=blocked square_asked=1 pin_asked=0 prepares=0 allow_enroll=-1 reason=PAIRED OPEN NOT CONFIRMED\n" if a.expect=="square" else
              "pending-paired state=listener square_asked=0 pin_asked=0 prepares=1 allow_enroll=0 reason=none\n")
    assert p.stdout==expected and p.stderr=="",(p.stdout,p.stderr)
    print(p.stdout,end="")
