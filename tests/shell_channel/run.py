"""Nonblocking shell editor, exact engine and authentic partial-input sequence (host)."""
from pathlib import Path
import os,subprocess,tempfile
here=Path(__file__).resolve().parent
src=here.parents[1]/'source'
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/('shell.exe' if os.name=='nt' else 'shell')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I',str(src),
                    str(here/'fixture.c'),*[str(src/f'{s}.c') for s in
                    ('wb_shell_channel','wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
