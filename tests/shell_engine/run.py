"""Build the deployed C command engine & WB parser, replay two independent shells."""
import os
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
SRC=HERE.parents[1]/"source"
with tempfile.TemporaryDirectory() as d:
    exe=Path(d)/("shell-fixture.exe" if os.name=="nt" else "shell-fixture")
    subprocess.run(["gcc","-std=c11","-O2","-Wall","-Wextra","-Werror","-I",str(SRC),
                    str(HERE/"fixture.c"),*[str(SRC/(n+".c")) for n in ("wb_shell","wb_cmd","wb_out","wb_str")],
                    "-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
