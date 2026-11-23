"""Native bounded-history tests. No filesystem/device I/O by the compiled fixture."""
from pathlib import Path
import subprocess,tempfile
h=Path(__file__).resolve().parent;s=h.parents[1]/'source'
with tempfile.TemporaryDirectory() as t:
    exe=Path(t)/'history.exe'
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-I'+str(s),str(h/'test_history.c'),str(s/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
