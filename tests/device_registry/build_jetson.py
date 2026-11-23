"""Build the candidate in a fresh owner-pinned Jetson workdir; no device access."""
from pathlib import Path
import datetime
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]
HOST=["ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=8","pi"]
DIGEST_INC="4327a32152d9cffa50a532cefd09d3e1737c601d832b953bc50c301b4a0a6737"
TEST_APP="f2609d1c89e88fd4b250019a0ca0160b97b2ad8b0028576310effac8fc990905"
PAYLOAD="0e3a633929b7069a5a194c86bd92eb770515d1766101f597139af61b0a45a66b"
def sha(b):return hashlib.sha256(b).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def main():
    files=[]
    for sub in ["source","payload","testapp","updater","tests/stub","tests/device_registry","tests/registry_table"]:
        files.extend(p for p in (ROOT/sub).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    files.extend(ROOT/p for p in ["unsupported_vita_calls.c","tools/gen_app_registry.py","tools/app_registry.py","tools/apps.txt","build/testapp.vpk"])
    files=sorted(files); names={p.relative_to(ROOT).as_posix():p for p in files}
    data={n:sha(p.read_bytes()) for n,p in names.items()}
    assert data["build/testapp.vpk"]==TEST_APP
    inherited={}
    for n in ["source/wb_ssh.c","source/wb_ssh.h","source/wb_host_identity.h","source/prep_gate.h","source/focus_guard.h","source/wb_ext_path_policy.h","payload/release_0122_p2_1.suprx"]:
        old=sha((ROOT.parent/"releases/v1.30"/n).read_bytes());assert old==data[n],n;inherited[n]=old
    e={"scope":"Isolated Jetson build with 5090 package verification. No Vita contact / no install.","started":utc(),"inputs_sha256":data,"unchanged_v1_30_inputs":inherited,"events":[]}
    receipt=ROOT/"build"/("attempt-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")+".json")
    def event(cmd,*,stdin=None,blob=False):
        cmd=list(map(str,cmd));p=subprocess.run(cmd,input=stdin,capture_output=True,cwd=ROOT,timeout=180)
        stdout=p.stdout.decode("utf8","replace") if not blob else None
        ev=dict(utc=utc(),argv=cmd,rc=p.returncode,stderr=p.stderr.decode("utf8","replace"))
        if blob:ev.update(stdout_bytes=len(p.stdout),stdout_sha256=sha(p.stdout))
        else:ev["stdout"]=stdout
        e["events"].append(ev);receipt.write_text(json.dumps(e,indent=2)+"\n",encoding="utf8")
        print("rc",p.returncode,cmd[-1][:140],(stdout or "")[-310:],ev["stderr"][-550:],flush=True)
        if p.returncode:raise RuntimeError("command failed, see "+str(receipt))
        return p.stdout if blob else stdout.strip()
    remote=event(HOST+["umask 077; mktemp -d /home/pi/.wb0131-registry.XXXXXXXX"])
    assert re.fullmatch(r"/home/pi/\.wb0131-registry\.[a-zA-Z0-9]{8}",remote);e["remote_workdir"]=remote
    lines="".join(h+"  "+n+"\n" for n,h in sorted(data.items())).encode()
    tar=io.BytesIO()
    with tarfile.open(fileobj=tar,mode="w:gz") as ar:
        for n,p in names.items():
            b=p.read_bytes();assert sha(b)==data[n];ti=tarfile.TarInfo(n);ti.size=len(b);ti.mode=0o755 if n.endswith(".sh") else 0o644;ar.addfile(ti,io.BytesIO(b))
        ti=tarfile.TarInfo("INPUTS.sha256");ti.size=len(lines);ar.addfile(ti,io.BytesIO(lines))
    event(HOST+[f"cd {remote} && tar xzf - && sha256sum --quiet -c INPUTS.sha256 && echo verified-build-inputs"],stdin=tar.getvalue())
    event([sys.executable,"-B","tests/device_registry/run.py"]);event([sys.executable,"-B","tests/registry_table/test_table.py"])
    # The host and target compilers differ. Exercise the branch fixture on the
    # Jetson as well, then run the exact target SDK package/verification steps.
    event(HOST+[f"cd {remote} && python3 -B tests/device_registry/run.py && cd source && sh build-jetson.sh --check && sh build-jetson.sh build"])
    event(HOST+[f"cd {remote} && sha256sum --quiet -c INPUTS.sha256 && sha256sum source/build/registry-generated/wb_registry_data.inc source/build/workbench_0131.vpk"])
    inc=event(HOST+[f"cat {remote}/source/build/registry-generated/wb_registry_data.inc"],blob=True)
    assert sha(inc)==DIGEST_INC
    vpk=event(HOST+[f"cat {remote}/source/build/workbench_0131.vpk"],blob=True)
    rel_digest=event(HOST+[f"sha256sum {remote}/source/build/workbench_0131.vpk"]).split()[0];assert sha(vpk)==rel_digest
    with zipfile.ZipFile(io.BytesIO(vpk)) as z:
        assert z.testzip() is None and len(z.namelist())==3
        eb=z.read("eboot.bin")
        assert all(lit in eb for lit in [b"01.31-live-registry1\0",TEST_APP.encode()+b"\0",b"INAP00020",b"registry-title",b"registry-version",b"registry-case",b"registry-sha256",b"savedata0:/wb-hi-key.bin"])
        assert sha(z.read("workbench_payload.suprx"))==PAYLOAD
    with tempfile.TemporaryDirectory(prefix="wb0131-verify-") as t:
        dest=Path(t)/"workbench_0131.vpk";dest.write_bytes(vpk)
        event([sys.executable,"-B","source/verify_package.py",t])
    assert all(sha(p.read_bytes())==data[n] for n,p in names.items()),"input changed during build; repeat isolated final build"
    build=ROOT/"build";target=build/"workbench_0131.vpk"
    if target.exists() and sha(target.read_bytes())!=rel_digest:raise ValueError("colliding different previous build; move aside explicitly")
    target.write_bytes(vpk);(build/"registry-generated.inc").write_bytes(inc)
    assert sha(target.read_bytes())==rel_digest
    e["result"]={"sha256":rel_digest,"bytes":len(vpk),"generated_registry_inc_sha256":sha(inc),"title":"INAP00018","version":"01.31","tag":"01.31-live-registry1","verified_utc":utc(),"installed":False}
    receipt.write_text(json.dumps(e,indent=2)+"\n",encoding="utf8")
    (build/"BUILD-VERIFICATION.json").write_bytes(receipt.read_bytes());print(e["result"],flush=True)
    return 0
if __name__=="__main__":sys.exit(main())
