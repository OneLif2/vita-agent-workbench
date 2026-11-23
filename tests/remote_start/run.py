"""Actual startup branch, matched identity and owner opt-out; SDK stubs only."""
from pathlib import Path
import argparse,subprocess,tempfile,shutil
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
p=argparse.ArgumentParser();p.add_argument('input',nargs='?',default='all',choices=['all','overlay-battery']);p.add_argument('--source',type=Path,default=ROOT/'source/vita_ssh_status.c');p.add_argument('--expect',choices=['listener','blocked'],default='listener');a=p.parse_args()
s=a.source.read_text(encoding='utf-8');begin='    load_config();';start=s.index(begin,s.index('int main(void)'));end=s.index('    if(return_ok){',s.index('if (wb_ssh_open(',start))
branch=s[start:end]
fixture=(D/'native.c.in').read_text(encoding='utf-8').replace('ACTUAL_STARTUP',branch)
b=s.index('        const bool input = ',s.index('int main(void)'));e=s.index('        /* Lock screen:',b)
fixture=fixture.replace('ACTUAL_RUNTIME_INPUT',s[b:e])
b=e;e=s.index('        const int served = ',b)
fixture=fixture.replace('ACTUAL_RUNTIME_GUARD',s[b:e])
b=s.index('static bool gate_ok(');e=s.index('static const wb_core g_core',b)
fixture=fixture.replace('ACTUAL_ADMISSION',s[b:e])

with tempfile.TemporaryDirectory(prefix='wb-remote-start-') as tmp:
 d=Path(tmp);c=d/'fixture.c';exe=d/'fixture.exe';c.write_text(fixture,encoding='utf-8')
 subprocess.run([shutil.which('gcc') or 'gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'source'),str(c),'-o',str(exe)],check=True)
 o=subprocess.run([str(exe),a.input,a.expect],capture_output=True,text=True);print(o.stdout,end='');print(o.stderr,end='',file=__import__('sys').stderr);assert o.returncode==0 and o.stderr==''
