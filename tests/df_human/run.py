"""Compile the real shell dispatch and capacity formatter; fake only the volume API result."""
import os,subprocess as sp,tempfile
from pathlib import Path
here=Path(__file__).resolve().parent;src=here.parents[1]/'source'
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/('df.exe' if os.name=='nt' else 'df')
    sp.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I',str(src),str(here/'fixture.c'),
            *[str(src/(name+'.c')) for name in ('wb_shell','wb_cmd','wb_str','wb_out')],'-o',str(exe)],check=True)
    sp.run([str(exe)],check=True)
