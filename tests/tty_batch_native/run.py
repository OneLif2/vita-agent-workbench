"""Actual C transfer engine + native adapter on mocked disk, and actual shell pump, offline."""
from argparse import ArgumentParser
from pathlib import Path
import hashlib, subprocess, tempfile
here=Path(__file__).resolve().parent; root=here.parents[1]; default=root/'source'
def cc(src,out,fixture,units,extra=()):
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',*extra,'-I'+str(src),
                    str(fixture),*[str(src/(x+'.c')) for x in units],'-o',str(out)],check=True)
def main():
    ap=ArgumentParser();ap.add_argument('--source',type=Path,default=default);ap.add_argument('--probe',action='store_true')
    a=ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='wb-tty-batch-') as d:
        d=Path(d); exe=d/'io.exe'
        cc(a.source,exe,here/'fixture.c',('wb_tty_file','wb_sha256','wb_path','wb_str'))
        def run(*argv):
            return subprocess.check_output([str(exe),*map(str,argv)],text=True,timeout=30)
        if a.probe:print(run('auto'),end='');return
        old=run('legacy');new=run('batch');assert 'sceIoWrite=2049 cumulative_ACK=2049' in old
        assert 'sceIoWrite=257 cumulative_ACK=257' in new and old.split('sha256=')[1]==new.split('sha256=')[1]
        print(old+new,end='')
        for n in (0,1,2047,2048,2049,16383,16384,16385,32768):
            r=run('batch',n);assert f'sceIoWrite={(n+16383)//16384} ' in r
        for scenario in ('gates','abort','cancel','end','dup','skip','overflow','short','hex',
                         'write','write-cleanup','latefail','digest','readback','sync','collision'):
            print(run(scenario),end='')
        # Use the normal shell/channel peer; partial I/O & echo, real command
        # recognition, and the suppressed intermediate responses are not mocks.
        bin=d/'shell.exe'
        cc(a.source,bin,here.parent/'tty_client/peer.c',
           ('wb_shell_channel','wb_tty_file','wb_shell','wb_cmd','wb_sha256','wb_out','wb_str'),['-DWB_TTY_FILE'])
        data=bytes(range(256))*64+b'x'; sha=hashlib.sha256(data).hexdigest().encode()
        command=b'put-batch "ux0:/VITA-POC/s.bin" '+str(len(data)).encode()+b' sha256='+sha+b'\n'
        frames=[b'D '+str(i).encode()+b' '+data[i:i+2048].hex().encode()+b'\n' for i in range(0,len(data),2048)]
        def shell(lines,rc):
            result=subprocess.run([str(bin)],input=b''.join(lines),capture_output=True,timeout=15)
            assert result.returncode==rc and not result.stderr,(result.returncode,result.stderr)
            return result.stdout
        got=shell([command,*frames,b'END\n',b'pwd\n',b'exit\n'],0)
        assert got.count(b'TTY1 ACK ')==2 and b'TTY1 ACK 16384\r\nTTY1 ACK 16385\r\n' in got
        assert b'TTY1 OK PUT 16385 '+sha+b'\r\nux0:/> ' in got and got.endswith(b'Bye.\r\n')
        assert data[:128].hex().encode() not in got
        bad=shell([command,frames[0],frames[0],b'pwd\n'],3)
        assert b'TTY1 ERR offset' in bad and b'ACK ' not in bad and b'pwd' not in bad
        print('PASS native batch, retained legacy behavior, no ACK for RAM/failed writes, actual shell ordered receipts, no command reinterpretation; host syscall model only.')
if __name__=='__main__':main()
