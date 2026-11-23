"""Actual archived command engine and WB parser; storage/dispatch boundaries use read-only trace stubs."""
import argparse,json,subprocess,tempfile
from pathlib import Path
H=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--source',type=Path,default=H.parents[1]/'source')
p.add_argument('--probe',action='store_true')
a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='wb-inbox-') as td:
    exe=Path(td)/'alias-probe.exe';src=a.source.resolve()
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I',str(src),str(H/'probe.c'),*[str(src/(x+'.c')) for x in ('wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(exe)],check=True)
    def go(*commands):
        return subprocess.run([str(exe),*commands],check=True,capture_output=True,text=True).stdout
    inp=['cd /inbox','pwd','ls -l .']
    reply=go(*inp)
    if a.probe:
        print(json.dumps({'input':inp,'stdout':reply,'exit':0},separators=(',',':')))
    else:
        assert reply=='ux0:/VITA-POC\nLIST 1 ux0:/VITA-POC\n',repr(reply)
        assert go('cd /inbox/','pwd','ls -l /inbox/.')==reply.splitlines()[0]+'\nLIST 1 ux0:/VITA-POC\n'
        assert go('cd "/inbox/folder one"','pwd','cd ..','pwd')=='ux0:/VITA-POC/folder one\nux0:/VITA-POC\n'
        assert go('cd /inbox/child/..','pwd','cd ..','pwd')=='ux0:/VITA-POC\nux0:/\n'
        assert go('cat "/inbox/sub dir/item.txt"')=='CAT ux0:/VITA-POC/sub dir/item.txt\n'
        assert go('ls -l /inbox/folder/../other')=='LIST 1 ux0:/VITA-POC/other\n'
        assert go('ls -l /','ls -l ux0:/inbox','ls -l /inbox2','ls -l /INBOX','ls -l inbox')=='LIST 1 ux0:/\nLIST 1 ux0:/inbox\nLIST 1 ux0:/inbox2\nLIST 1 ux0:/INBOX\nLIST 1 ux0:/inbox\n'
        assert go('stat /inbox/item')=='CORE stat [ux0:/VITA-POC/item]\n'
        assert go('mv /inbox/a "/inbox/folder one/b"')=='CORE mv [ux0:/VITA-POC/a] [ux0:/VITA-POC/folder one/b]\n'
        assert go('app plan /inbox/example.vpk').endswith(' [ux0:/VITA-POC/example.vpk]\n')
        for command in ('mkdir /inbox','rm /inboxevil/file','mv /inbox/a /data/INAP00018/no','rm /inbox/../../outside','rm /inbox/../VITA-POC/other','rm /inbox/sub/../../other','ls /inbox/..','cat /inbox//child','ls /inbox/../data','cat /inbox/ux0:/foo','ls /inbox/bad*','ls /inbox/new.','ls /inbox/'+'a'*101,'ls /inbox/'+'a'*100+'/'+'b'*14):
            answer=go(command)
            assert answer.startswith('ERR ') and len(answer.splitlines())==1 and 'CORE ' not in answer,(command,answer)
        maxpath='/inbox/'+'a'*100+'/'+'b'*12
        assert len('ux0:/VITA-POC/'+maxpath[len('/inbox/'):])==127
        assert go('ls '+maxpath)=='LIST 0 ux0:/VITA-POC/'+maxpath[len('/inbox/'):]+ '\n'
        assert go('cd /inbox','cd /inbox/..','pwd')=='ERR invalid ux0 path\nux0:/VITA-POC\n'
        assert '/inbox = ux0:/VITA-POC' in go('help files')
        print('PASS native shell alias: canonical navigation, spaces/list/cat, core operand mapping, anchor traversal/sibling/bounds/no root writes, failed cd preserves cwd. No network or storage writes.')
