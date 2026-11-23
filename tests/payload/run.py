"""Build a local native fixture, never a payload for the Vita.
Usage: python run.py [CANDIDATE_PAYLOAD_MAIN_C] [--cc gcc]
Exit 0 if all cases pass, 1 on regression, or compiler status on build failure.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

def main():
    here=Path(__file__).resolve().parent
    root=here.parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", nargs="?", type=Path, default=root/"payload/payload_main.c")
    p.add_argument("--cc", default="gcc")
    a=p.parse_args()
    src=a.source.resolve(strict=True)
    cc=shutil.which(a.cc)
    if not cc: p.error("C compiler not found: "+a.cc)
    with tempfile.TemporaryDirectory(prefix="wb-b9-b10-") as tmp:
        td=Path(tmp)
        data=src.read_bytes()
        (td/"payload-under-test.c").write_bytes(data)
        shutil.copyfile(here/"payload_cases.c",td/"payload_cases.c")
        exe=td/("check.exe" if sys.platform=="win32" else "check")
        cmd=[cc,"-std=c11","-Wall","-Wextra","-Werror","-O1",
             "-I",str(root/"tests/stub"),"-I",str(root/"source"),
             str(td/"payload_cases.c"),"-o",str(exe)]
        print(f"source={src} sha256={hashlib.sha256(data).hexdigest()}",flush=True)
        cp=subprocess.run(cmd)
        if cp.returncode:return cp.returncode
        return subprocess.run([str(exe)]).returncode
if __name__=="__main__":sys.exit(main())
