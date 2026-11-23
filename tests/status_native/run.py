"""Compile actual Workbench shell/snapshot function with SDK input stubs."""
import subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
S=HERE.parents[1]/'source'
def build(d,shell=None,parser=None):
    src=(S/'vita_ssh_status.c').read_text(encoding='utf8')
    i=src.index('        case WB_CMD_TERM_WB_STATUS:')
    (d/'dispatch.inc').write_text(src[i:src.index('        case WB_CMD_TERM_R1_SIGNED:',i)],encoding='utf8')
    exe=d/'status.exe'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(d),'-I'+str(S),
                    str(HERE/'native.c'),str(shell or S/'wb_shell.c'),str(parser or S/'wb_cmd.c'),
                    *(str(S/(n+'.c')) for n in ('wb_out','wb_str','wb_err')),'-o',str(exe)],check=True)
    return exe
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:
        exe=build(Path(t));subprocess.run([str(exe)],check=True)
