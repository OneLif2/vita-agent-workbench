"""Offline: compile the native shell, actual dispatch case and directory-only fixture."""
import os
from pathlib import Path
import subprocess
import tempfile

D = Path(__file__).resolve().parent
R = D.parents[1]
S = R / 'source'

def build(t, shell=None):
    src = (S/'vita_ssh_status.c').read_text()
    start = src.index('        case WB_CMD_TERM_CRASH_INDEX:')
    end = src.index('        case ', start+1)
    (t/'dispatch_under_test.inc').write_text(src[start:end], encoding='ascii')
    binary = t/('native.exe' if os.name=='nt' else 'native')
    cmd = [os.environ.get('CC','gcc'),'-std=c11','-O2','-Wall','-Wextra','-Werror',
           '-I'+str(t),'-I'+str(S),'-I'+str(R/'tests/stub'),str(D/'native.c'),str(shell or S/'wb_shell.c'),
           *(str(S/(f+'.c')) for f in ('wb_cmd','wb_str','wb_out','wb_err')), '-o',str(binary)]
    subprocess.run(cmd,check=True)
    return binary, cmd

if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        exe, _ = build(Path(tmp))
        subprocess.run([str(exe)],check=True)
