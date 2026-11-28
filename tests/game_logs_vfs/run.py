"""Actual C VFS policy / exact-entry walk; no device. --probe accepts --source for rollback."""
from pathlib import Path
import argparse,os,subprocess,tempfile
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=ROOT/'source');p.add_argument('--probe',action='store_true');a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='wb-game-logs-vfs-') as tmp:
 exe=Path(tmp)/('probe.exe' if os.name=='nt' else 'probe')
 flags=['-DWB_TEST_GAME_READ_API'] if 'int wb_vita_shell_open_game_log(' in (a.source/'wb_shell_vfs.c').read_text() else []
 cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(ROOT/'tests/stub'),'-I'+str(a.source),str(D/'fixture.c'),str(a.source/'wb_shell_vfs.c'),str(a.source/'wb_out.c'),'-o',str(exe)]
 subprocess.run(cmd,check=True)
 subprocess.run([str(exe),*(['--probe'] if a.probe else [])],check=True)
