"""Build/execute the real v1.33 core R1 functions on an in-memory host device."""
from pathlib import Path
import os, subprocess, tempfile, sys
here=Path(__file__).resolve().parent
root=here.parents[1]
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/("core.exe" if os.name=="nt" else "core")
    subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror","-I",str(root/"tests/stub"),"-I",str(root/"tests/host_identity/sim"),"-I",str(root/"source"),str(here/"fixture.c"),"-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
    subprocess.run([sys.executable,"-B",str(root/"tests/dispatch/startup_owner.py")],check=True)
    subprocess.run([sys.executable,"-B",str(here/"gates.py")],check=True)
