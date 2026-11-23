"""Offline PTY terminal contract; uses no network or filesystem adapter."""
from pathlib import Path
import os,subprocess,tempfile
d=Path(__file__).resolve().parent;s=d.parents[1]/"source"
with tempfile.TemporaryDirectory() as td:
 exe=Path(td)/("settings.exe" if os.name=="nt" else "settings")
 subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror","-I"+str(s),str(d/"fixture.c"),*[str(s/(k+".c")) for k in ("wb_shell","wb_cmd","wb_str","wb_out")],"-o",str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
