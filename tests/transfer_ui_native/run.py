"""Execute the production frame path; only the GXM/dialog driver calls are stubbed."""
from pathlib import Path
import os, subprocess, tempfile
d=Path(__file__).resolve().parent
src=d.parents[1]/'source'
code=(src/'display.c').read_text()
with tempfile.TemporaryDirectory() as td:
    t=Path(td)
    (t/'frame.inc').write_text(code[code.index('static uint64_t last_xfer_present;'):code.index('static void put32le')])
    exe=t/('frame.exe' if os.name=='nt' else 'frame')
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(src),'-I'+td,str(d/'fixture.c'),str(src/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
    subprocess.run([exe],check=True,timeout=20)
