"""Production adapter + protocol, injected storage syscalls. No network or Vita."""
from pathlib import Path
import argparse, subprocess, tempfile, shutil
HERE=Path(__file__).resolve().parent
S=HERE.parents[1]/'source'
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--adapter',type=Path);p.add_argument('--protocol',type=Path)
    p.add_argument('--probe',choices=['combo','zero','oversize','short','tail','cancel','finish'])
    opt=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='wb-tty-io-') as tmp:
        d=Path(tmp);exe=d/'probe.exe'
        if opt.adapter:shutil.copyfile(opt.adapter,d/'wb_tty_vita.inc')
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(d),'-I'+str(S),str(HERE/'fixture.c'),str(opt.protocol or S/'wb_tty_file.c'),*[str(S/(x+'.c')) for x in ('wb_sha256','wb_path','wb_str')],'-o',str(exe)],check=True)
        def run(mode):return subprocess.check_output([str(exe),mode],text=True,timeout=10)
        if opt.probe:print(run(opt.probe),end='');return
        cases={'combo':['write-error rc=0x80010005 offset=2 requested=1','cleanup-error rc=0x80010013','published=0 private=1'],
               'zero':['write-error rc=0x00000000 offset=0 requested=3','published=0 private=0'],
               'oversize':['write-error rc=0x00000004 offset=0 requested=3','published=0 private=0'],
               'short':['TTY1 ACK 3','TTY1 OK PUT 3 ba7816','published=1 private=0'],
               'tail':['TTY1 ACK 1','write-error rc=0x00000000 offset=1 requested=2','published=0 private=0'],
               'cancel':['TTY1 ERR cancelled','cleanup-error rc=0x80010013','terminal_rc=-1 published=0 private=1'],
               'finish':['sync-error rc=0x80010005','close-error rc=0x80010009','cleanup-error rc=0x80010013','terminal_rc=-1 published=0 private=1']}
        for k,need in cases.items():
            got=run(k)
            if not all(s in got for s in need) or (k!='short' and 'TTY1 OK' in got):raise AssertionError((k,got,need))
            print(k,got.rstrip(),sep=': ')
        print('PASS: 7 native-adapter TTY1 fault/short-write cases; no device access')
if __name__=='__main__':main()
