"""Compile the actual read-only Vita adapter and SFTP path predicate against SDK I/O stubs."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

r = Path(__file__).resolve().parents[2]
src = r / "source"
with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / ("adapter.exe" if os.name == "nt" else "adapter")
    cmd = ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
           "-I", str(src), "-I", str(r / "tests/stub"),
           str(Path(__file__).with_name("fixture.c")), str(src / "wb_sftp_vita.c"),
           str(src / "wb_sftp_ro.c"), str(src / "wb_path.c"), "-o", str(exe)]
    subprocess.run(cmd, check=True)
    result = subprocess.run([str(exe)], check=True, text=True, capture_output=True)
    print(result.stdout, end="")
    prefix = "native file bytes: "
    wire = bytes.fromhex(next(l[len(prefix):] for l in result.stdout.splitlines() if l.startswith(prefix)))
    want = bytes([0, 255, 66, 13, 10, 0, 128, 33])
    assert hashlib.sha256(want).digest() == hashlib.sha256(wire).digest()
    print("host fixture SHA-256:", hashlib.sha256(wire).hexdigest())
