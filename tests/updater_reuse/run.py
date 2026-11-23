"""Exercise the real before/after wb_updater_install, with Vita OS calls replaced.

--observe --root PATH: same inputs, literal counters, no version-specific expectations.
No device, app.db, network access, or shell folder emulation.
"""
from pathlib import Path
import argparse, hashlib, os, struct, subprocess, sys, tempfile, zipfile
HERE = Path(__file__).resolve().parent
REL = HERE.parents[1]
PROJECT = REL.parent
SFO = "1dba3e69e2647c12bf6a094c291dc210cdc651b7bbad11c3d6cdef63b3a4fe1b"
BOOT = {"173": "53bc94ee1418a73339965da45a110562caa34bd63778c7f81f21e63f2e1189a8",
        "174": "3db1718a22be8c4a2916e41e2dae1d1930fd881c958b7163862f76b6093deb3b"}
MUTATIONS = ("promotes", "stage_removes", "stage_mkdirs", "stage_write_opens", "stage_writes")
BAD = ("bad-eboot","wrong-title","wrong-version","partial-eboot","partial-sfo",
       "orphan-members","orphan-unregistered","wrong-size","unregistered-files","registered-missing",
       "registry-error","stat-error","not-regular","open-error","read-error","early-eof","close-error","data-beyond-stat","too-long-read")

def check(cond, why):
    if not cond: raise AssertionError(why)

def extract(code):
    archive = PROJECT/f"v1.{code[1:]}/build/workbench_0{code}.vpk"
    with zipfile.ZipFile(HERE/"helper-samples.zip") as samples:
        eb=samples.read(code+".eboot"); sf=samples.read("shared.sfo")
        check(len(eb)==161438 and len(sf)==912 and hashlib.sha256(eb).hexdigest()==BOOT[code] and hashlib.sha256(sf).hexdigest()==SFO, "invalid helper test input")
    if not archive.exists(): return eb,sf
    with zipfile.ZipFile(archive) as z:
        core=z.read("eboot.bin")
    at=core.find(b"SCE\0",4)
    while at>=0:
        if at+40<=len(core) and struct.unpack_from("<Q",core,at+32)[0]==161438:
            eb=core[at:at+161438]; sf=core[at+161438:at+161438+912]
            if hashlib.sha256(eb).hexdigest()==BOOT[code] and hashlib.sha256(sf).hexdigest()==SFO:
                return eb,sf
        at=core.find(b"SCE\0",at+1)
    raise AssertionError(f"trusted release helper not found: {archive}")

def compile_root(root, tmp, wrong_embed=None):
    src=root if (root/"wb_updater.c").exists() else root/"source"
    blobs=extract("174"); old=extract("173"); asm=[]
    for sym,name,b in [("_binary_updater_eboot_bin","eboot",blobs[0]),("_binary_updater_param_sfo","sfo",blobs[1]),("_historical_eboot","old",old[0])]:
        if name==wrong_embed: b=bytes([b[0]^1])+b[1:]
        (tmp/name).write_bytes(b)
        asm += [".data",".balign 4",f".globl {sym}_start",f".globl {sym}_end",f"{sym}_start:",f'.incbin "{name}"',f"{sym}_end:"]
    (tmp/"blobs.S").write_text("\n".join(asm)+"\n")
    exe=tmp/("probe.exe" if os.name=="nt" else "probe")
    args=[os.environ.get("CC","gcc"),"-std=c11","-Wall","-Wextra","-Werror","-O2","-I"+str(src),"-I"+str(REL/"tests/stub"),str(HERE/"fixture.c"),"blobs.S"]
    args.extend(str(src/(f+".c")) for f in ("wb_updater","wb_head","wb_sha1","wb_sha256","wb_sfo","wb_str"))
    has_probe="wb_updater_probe(" in (src/"wb_updater.h").read_text()
    args.append("-DHAS_PROBE="+str(int(has_probe)))
    if has_probe:
        c=(src/"vita_ssh_status.c").read_text()
        start=c.index("        case WB_CMD_TERM_UPDATER_CHECK:")
        (tmp/"adapter.inc").write_text(c[start:c.index("        case ",start+12)])
        args.append("-I"+str(tmp))
        args.extend(str(src/(f+".c")) for f in ("wb_cmd","wb_out","wb_err","wb_shell"))
    subprocess.run([*args,"-o",str(exe)],cwd=tmp,check=True)
    return exe

def run(exe,case, echo=True):
    p=subprocess.run([str(exe),case],capture_output=True,text=True,timeout=15)
    if p.returncode or p.stderr:
        raise AssertionError((case,p.returncode,p.stdout,p.stderr))
    data=[dict((k,int(v)) for k,v in (part.split("=") for part in line.split())) for line in p.stdout.splitlines()]
    check(data,case)
    if echo: print(case+": "+p.stdout.strip().replace("\n"," ; "))
    return data

def counts(row):
    return [row[k] for k in MUTATIONS]

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--root",type=Path,default=REL);ap.add_argument("--observe",action="store_true")
    opt=ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="wb-helper-") as d:
        exe=compile_root(opt.root.resolve(),Path(d))
        if opt.observe:
            for c in ("matching-three","historic-three","absent-then-two","bad-eboot","registry-error"):
                run(exe,c)
            return
        for case in ("matching-three","historic-three"):
            rows=run(exe,case)
            check(len(rows)==3 and all(r["rc"]==0 and r["detail"]==1 and counts(r)==[0]*5 and r["queries"] for r in rows),case)
        rows=run(exe,"absent-then-two"); a=rows[0]
        check(len(rows)==3 and a["rc"]==0 and a["detail"]==0 and a["promotes"]==1 and a["stage_write_opens"]==3 and a["queries"]>=2,"initial install")
        check(all(r["rc"]==0 and r["detail"]==1 and counts(r)==counts(a) for r in rows[1:]),"reinstall after bootstrap")
        for c in BAD:
            (r,)=run(exe,c); check(r["rc"]<0 and counts(r)==[0]*5,c)
        (r,)=run(exe,"short-reads");check(r["rc"]==0 and counts(r)==[0]*5,"partial read iteration")
        (r,)=run(exe,"stage-write-error");check(r["rc"]<0 and r["stage_write_opens"]==1 and not r["promotes"],"no partial promote")
        for c in ("promote-error","bad-post-promote"):
            (r,)=run(exe,c);check(r["rc"]<0 and r["promotes"]==1,c)
        for case,rc,detail in (("racing-match",0,1),("racing-bad",-8,0)):
            (r,)=run(exe,case);check(r["rc"]==rc and r["detail"]==detail and not r["promotes"] and r["stage_write_opens"]==3,case)
        (r,)=run(exe,"stale-stage");check(r["rc"]==0 and r["promotes"]==1 and r["stage_removes"]==1,"stale stage bootstrap")
        (r,)=run(exe,"stage-stat-error");check(r["rc"]<0 and counts(r)==[0]*5,"stage stat IO")
        for case,mode,text,expected in [
           ("matching-three","paired","helper=reuse epoch=01.74 promote=0",(0,1,1)),
           ("historic-three","paired","helper=reuse epoch=01.73 promote=0",(0,1,1)),
           ("absent-then-two","paired","helper=absent promote=0",(0,1,1)),
           ("wrong-version","paired","helper=refuse phase=unknown-identity",(1,1,1)),
           ("registry-error","paired","helper=refuse phase=registration",(1,1,1)),
           ("matching-three","bad-args","ERR usage: updater check",(0,0,0)),
           *[("matching-three",m,"ERR paired interactive PTY required",(1,0,1))
              for m in ("unpaired","unauthenticated","no-pty","sftp")]]:
            q=subprocess.run([str(exe),case,mode],text=True,capture_output=True,check=True)
            s,n,called=expected
            check(not q.stderr and text in q.stdout and f"core_status={s} queries={n} dispatches={called} stage_mutations=0 promotes=0" in q.stdout,(case,mode,q.stdout))
            print("shell:",mode,case,q.stdout.strip().replace("\n"," ; "))
        for name in ("eboot","sfo"):
            bad=Path(d)/("embedded-"+name);bad.mkdir()
            b=compile_root(opt.root.resolve(),bad,wrong_embed=name)
            for r in run(b,"absent-then-two",echo=False):
                check(r["rc"]<0 and counts(r)==[0]*5,"untrusted embedded "+name)
            print("embedded-"+name+": refused bootstrap before any writes or promotion")
        print("PASS updater_reuse: exact known release helpers, zero stage writes on reuse/refusal, bootstrap once, promotion/IO failures closed (host only)")
if __name__=="__main__": main()
