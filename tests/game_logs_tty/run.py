"""Production TTY adapter and TTY1 state machine with a checked-log API double.
No Vita/network. The production VFS walk is covered separately by game_logs_vfs.
--adapter/--probe supports the same immutable fixture against the parent adapter.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter',type=Path)
    parser.add_argument('--probe',action='store_true')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='wb-game-logs-tty-') as tmp:
        out=Path(tmp)
        if args.adapter:shutil.copyfile(args.adapter,out/'wb_tty_vita.inc')
        exe=out/('logs.exe' if os.name=='nt' else 'logs')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(out),'-I'+str(ROOT/'source'),
                        str(HERE/'probe.c'),*[str(ROOT/'source'/(name+'.c')) for name in
                        ('wb_sha256','wb_str','wb_path','wb_tty_file')],'-o',str(exe)],check=True)
        subprocess.run([str(exe)]+(['--probe'] if args.probe else []),check=True,timeout=15)
if __name__=='__main__':main()
