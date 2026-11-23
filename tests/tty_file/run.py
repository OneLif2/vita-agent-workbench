"""Host regression: actual authenticated-shell channel's transfer engine, mocked storage/transport."""
import os, subprocess, tempfile
from pathlib import Path
here=Path(__file__).resolve().parent
src=here.parents[1]/'source'
with tempfile.TemporaryDirectory() as d:
    exe=Path(d)/('tty-file.exe' if os.name=='nt' else 'tty-file')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-DWB_TTY_FILE','-DWB_SCREEN_MIRROR',
                    '-I',str(src),str(here/'fixture.c'),*[str(src/(n+'.c')) for n in
                    ('wb_shell_channel','wb_shell','wb_tty_file','wb_cmd','wb_out','wb_str','wb_sha256','wb_screen_mirror')],
                    '-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
