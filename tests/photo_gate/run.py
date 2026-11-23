"""Compile the real command/parser/hash, stub only filesystem and platform Photos."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

D = Path(__file__).resolve().parent
S = D.parents[1] / "source"
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--jpeg", type=Path, default=D/"tile.jpg",
                help="also exercise the gate against a specific JPEG fixture (<=8 MiB)")
argv = ap.parse_args()
with tempfile.TemporaryDirectory() as td:
    exe = Path(td) / ("photo-gate.exe" if os.name == "nt" else "photo-gate")
    subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                    "-I"+str(S), str(D/"fixture.c"),
                    *[str(S/(n+".c")) for n in ("wb_photo_gate","wb_sha256","wb_cmd","wb_out")],
                    "-o", str(exe)], check=True)
    args=[]
    for p in [argv.jpeg, D/"tile.png"]:
        args += [str(p), hashlib.sha256(p.read_bytes()).hexdigest()]
    subprocess.run([str(exe), *args], check=True)
