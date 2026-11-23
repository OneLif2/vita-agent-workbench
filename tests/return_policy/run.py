"""5090 native host R1 policy tests: no connection, no Vita filesystem."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    policy = ROOT / "source/wb_return_policy.h"
    result = {"scope": "native host simulation, no Vita", "events": [],
              "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory() as td:
        exe = Path(td)/("r1.exe" if os.name=="nt" else "r1")
        for cmd in (["gcc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                     "-I",str(policy.parent),str(HERE/"policy.c"),"-o",str(exe)], [str(exe)]):
            p = subprocess.run(cmd, capture_output=True, text=True)
            result["events"].append(dict(argv=cmd,rc=p.returncode,stdout=p.stdout,stderr=p.stderr))
            print(p.stdout+p.stderr,end="")
            if p.returncode: break
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
    return p.returncode

if __name__ == "__main__": sys.exit(main())
