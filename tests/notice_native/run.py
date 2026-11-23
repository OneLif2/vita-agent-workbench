"""Compile actual r1-notice terminal case and sealed queue code against host stubs, no Vita I/O."""
import os,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
S=D.parents[1]/'source'
def build(t,shell=None):
    src=(S/'vita_ssh_status.c').read_text()
    start=src.index('        case WB_CMD_TERM_R1_NOTICE:')
    (t/'dispatch.inc').write_text(src[start:src.index('        case WB_CMD_TERM_USER_STATUS:',start)])
    hdr=(S/'wb_return_vita.h').read_text()
    start=hdr.index('static bool r1_queue(')
    (t/'queue.inc').write_text(hdr[start:hdr.index('/* Only invoked',start)])
    exe=t/('notice.exe' if os.name=='nt' else 'notice')
    cmd=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-I'+str(t),'-I'+str(S),
         str(D/'native.c'),str(shell or S/'wb_shell.c'),
         *(str(S/(f+'.c')) for f in ('wb_cmd','wb_str','wb_out','wb_err')),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    return exe
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:subprocess.run([str(build(Path(t)))],check=True)
