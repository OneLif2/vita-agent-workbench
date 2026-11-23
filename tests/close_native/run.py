"""Compile actual paired-shell close guard against host transports; no device I/O."""
import os,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
S=D.parents[1]/'source'
def build(t,shell=None):
    src=(S/'vita_ssh_status.c').read_text(encoding='utf8')
    i=src.index('        case WB_CMD_TERM_CLOSE_WB:')
    (t/'close.inc').write_text(src[i:src.index('        case WB_CMD_TERM_R1_REVIEW:',i)],encoding='utf8')
    exe=t/('close-probe.exe' if os.name=='nt' else 'close-probe')
    cmd=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-I'+str(t),'-I'+str(S),
         str(D/'native.c'),str(shell or S/'wb_shell.c'),*(str(S/(n+'.c')) for n in ('wb_cmd','wb_str','wb_out','wb_err')),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    return exe
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:subprocess.run([str(build(Path(t)))],check=True)
