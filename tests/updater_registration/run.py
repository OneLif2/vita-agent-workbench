"""Offline qualification of the exact native registration adapter and PTY descriptor."""
from pathlib import Path
import os, subprocess, tempfile
D=Path(__file__).resolve().parent
R=D.parents[1]
S=R/'source'
def section(file, first, end):
    text=(S/file).read_text(); a=text.index(first); return text[a:text.index(end,a)]
with tempfile.TemporaryDirectory() as td:
    t=Path(td)
    (t/'wb_controls_under_test.inc').write_text(section('wb_ssh_vita_uninstall.inc','#define WBU_ID','static int wbu_hash_file('))
    (t/'wb_check_cmd_under_test.inc').write_text(section('vita_ssh_status.c','        case WB_CMD_TERM_UPDATER_CHECK:', '        case WB_CMD_R1_STATUS:'))
    binary=t/('test.exe' if os.name=='nt' else 'test')
    subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-O2',
        '-I'+str(t),'-I'+str(S),'-I'+str(R/'tests/stub'),str(D/'registration.c'),
        *[str(S/(n+'.c')) for n in ['wb_shell','wb_cmd','wb_str','wb_out','wb_err']],'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
