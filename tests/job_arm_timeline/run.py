"""Exercise real 01.32 S4/C2 functions with in-memory storage and no network."""
from pathlib import Path
import os,subprocess,tempfile,sys
here=Path(__file__).resolve().parent
r=here.parents[1]
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/('check.exe' if os.name=='nt' else 'check')
    cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror','-I',str(r/'tests/stub'),'-I',str(r/'tests/host_identity/sim'),'-I',str(r/'source'),str(here/'fixture.c'),str(r/'source/wb_timeline.c'),str(r/'source/wb_out.c'),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    subprocess.run([str(exe)],check=True)
    subprocess.run([sys.executable,'-B',str(r/'tests/dispatch/startup_owner.py')],check=True)

