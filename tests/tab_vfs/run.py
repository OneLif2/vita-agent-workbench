"""Compile both actual shipped C implementations; SDK directory calls alone are fake."""
from pathlib import Path
import os, subprocess, tempfile
here=Path(__file__).resolve().parent
r=here.parents[1];src=r/"source"
with tempfile.TemporaryDirectory() as d:
    exe=Path(d)/("probe.exe" if os.name=="nt" else "probe")
    subprocess.run(["gcc","-std=c11","-O2","-Wall","-Wextra","-Werror","-I",str(r/"tests/stub"),"-I",str(src),
                    str(here/"probe.c"),*[str(src/(n+".c")) for n in ("wb_shell","wb_shell_vfs","wb_cmd","wb_str","wb_out")],
                    "-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
