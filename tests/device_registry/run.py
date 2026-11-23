"""Execute the actual device app-install/launch gate offline with simulated FS and promoter.

Inputs are the approved, inert-in-this-process TestApp bytes and ordinary valid
VPK/SFO identity variants. No SSH, installation, process launch, or device I/O.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def repackage(data, new_sfo):
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out,"w") as dst:
        for item in src.infolist():
            dst.writestr(item, new_sfo if item.filename=="sce_sys/param.sfo" else src.read(item))
    return out.getvalue()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    here=Path(__file__).resolve().parent
    p.add_argument("--root",type=Path,default=here.parents[1])
    p.add_argument("--testapp",type=Path,help="approved TestApp VPK (data only)")
    p.add_argument("--ssh-vita",type=Path,help="official 1.4.2 VPK (data only)")
    p.add_argument("--cc",default="gcc"); a=p.parse_args()
    root=a.root.resolve(); src=root/"source"
    cc=shutil.which(a.cc); assert cc,"host C compiler required"
    default_testapp=root/"build/testapp.vpk"
    if not default_testapp.is_file(): default_testapp=root.parent/"v1.54/build/testapp.vpk"
    data=(a.testapp or default_testapp).read_bytes()
    assert hashlib.sha256(data).hexdigest()=="fea70dc69399200bdf00ca145044cac7725b4987d19da9d032ff2dbfd12a43e9"
    ssh_vita=(a.ssh_vita or root.parent/"external/ssh-vita/v1.4.2/upstream/ssh-vita.vpk").read_bytes()
    assert hashlib.sha256(ssh_vita).hexdigest()=="e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce"
    with zipfile.ZipFile(io.BytesIO(ssh_vita)) as z:
        ssh_sfo=z.read("sce_sys/param.sfo"); ssh_eboot=z.read("eboot.bin")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        sfo=z.read("sce_sys/param.sfo"); eboot=z.read("eboot.bin")
    wrong_title=sfo.replace(b"INAP00020\0",b"INAP00099\0")
    wrong_version=sfo.replace(b"01.01\0",b"01.99\0")
    assert wrong_title!=sfo and wrong_version!=sfo
    altered=io.BytesIO(data)
    with zipfile.ZipFile(altered,"a") as z: z.comment=b"QA identity variant; original program members unchanged"
    with tempfile.TemporaryDirectory(prefix="wb-registry-qa-") as tmp:
        d=Path(tmp)
        g=d/"wb_registry_data.inc"
        subprocess.run([sys.executable,"-B",str(root/"tools/gen_app_registry.py"),str(g)],check=True)
        exe=d/("gate.exe" if os.name=="nt" else "gate")
        subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror","-O1","-I",str(d),"-I",str(src),"-I",str(root/"tests/stub"),
                        str(here/"gate_fixture.c"),*(str(src/(n+".c")) for n in (
                            "wb_zip","wb_inflate","wb_crc32","wb_sfo","wb_out","wb_str","wb_path","wb_sha256","wb_sha1","wb_head","wb_err")),"-o",str(exe)],check=True)
        cases=[
            ("plan-approved",data,sfo), ("plan-case-denied",data,sfo), ("plan-sha-denied",altered.getvalue(),sfo),
            ("install-approved",data,sfo),("install-title-denied",repackage(data,wrong_title),sfo),
            ("install-version-denied",repackage(data,wrong_version),sfo),
            ("install-sha-denied",altered.getvalue(),sfo),("install-short-read",data,sfo),
            ("install-snapshot-immutable",data,sfo),("install-stage-write-failed",data,sfo),
            ("launch-approved",data,sfo),("launch-title-denied",data,sfo),
            ("launch-case-denied",data,sfo),("launch-installed-version-denied",data,wrong_version),
            ("launch-platform-failed",data,sfo),
        ]
        record=b"job=TEST_0001\ntitle=INAP00020\ncase=fs-smoke\nbuild=01.01-testapp\nassert=write=64 read=64 match=1\nresult=PASS\n"
        bad=b"write=64 read=63 match=0"
        for name,result in {
            "pass":record,"power":record.replace(b"fs-smoke",b"power-smoke").replace(b"write=64 read=64 match=1",b"battery=99 temp_raw=3000"),
            "compute":record.replace(b"fs-smoke",b"compute-smoke").replace(b"write=64 read=64 match=1",b"fnv1a=0x655C5FFD expected=0x655C5FFD"),
            "fail":record.replace(b"write=64 read=64 match=1",bad).replace(b"PASS",b"FAIL"),
            "contradiction":record.replace(b"write=64 read=64 match=1",bad),"job":record.replace(b"TEST_0001",b"STALE"),
            "duplicate":record+b"result=PASS\n","build":record.replace(b"01.01",b"01.00"),
            "title":record.replace(b"INAP00020",b"INAP00019"),"case":record.replace(b"fs-smoke",b"unknown"),
            "nul":record+b"junk\0","too-big":b"A"*1025,
        }.items():cases.append(("result-"+name,data,result))
        for name,pkg,installed in cases:
            (d/"fixture.vpk").write_bytes(pkg);(d/"installed.sfo").write_bytes(installed)
            subprocess.run([str(exe),name,str(d/"fixture.vpk"),str(d/"installed.sfo"),hashlib.sha256(eboot).hexdigest()],check=True)
        alt=io.BytesIO(ssh_vita)
        with zipfile.ZipFile(alt,"a") as z: z.comment=b"ordinary archive-comment change"
        ssh_cases=[
          ("install-approved-ssh-vita",ssh_vita),
          ("launch-install-only-title-denied",ssh_vita),
          ("install-sha-denied",alt.getvalue()),
          ("install-title-denied",repackage(ssh_vita,ssh_sfo.replace(b"VSSH00001\0",b"VSSH00002\0"))),
          ("install-version-denied",repackage(ssh_vita,ssh_sfo.replace(b"01.42\0",b"01.43\0"))),
        ]
        for name,pkg in ssh_cases:
            (d/"fixture.vpk").write_bytes(pkg);(d/"installed.sfo").write_bytes(ssh_sfo)
            subprocess.run([str(exe),name,str(d/"fixture.vpk"),str(d/"installed.sfo"),hashlib.sha256(ssh_eboot).hexdigest()],check=True)
    print(f"PASS {len(cases)+len(ssh_cases)} actual gate branches with mock Vita I/O; no device connection")
    return 0

if __name__=="__main__":sys.exit(main())
