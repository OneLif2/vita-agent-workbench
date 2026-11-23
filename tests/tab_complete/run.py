"""Build real interactive shell + read-only completion; deterministic transport and filesystem."""
from pathlib import Path
import os, subprocess, tempfile
p=Path(__file__).resolve().parent
s=p.parents[1]/'source'
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/('tab.exe' if os.name=='nt' else 'tab')
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-DWB_GAME_FEATURE',
                    '-I'+str(s),str(p/'fixture.c'),
                    *[str(s/(stem+'.c')) for stem in ('wb_shell_channel','wb_shell','wb_cmd','wb_out','wb_str')],
                    '-o',str(exe)],check=True,timeout=60)
    subprocess.run([str(exe)],check=True,timeout=10)
