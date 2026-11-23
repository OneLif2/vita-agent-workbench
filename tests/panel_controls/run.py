"""Use actual 01.69 key dispatch, mirror, and per-buffer cache. No Vita or network."""
from pathlib import Path
import subprocess,tempfile
HERE=Path(__file__).resolve().parent;SRC=HERE.parents[1]/'source'
s=(SRC/'vita_ssh_status.c').read_text()
origin=s.index('const bool input = sceCtrlPeekBufferPositive')
a=s.index('        if(input && wb_mirror_active()){',origin)
b=s.index('        if(input && !pad.buttons)local_released=true;',a)
assert 'SCE_CTRL_START' in s[origin:a]
assert 'pad.buttons==SCE_CTRL_TRIANGLE' in s[b:] and 'SCE_CTRL_SELECT|SCE_CTRL_SQUARE' in s[b:]
display=(SRC/'display.c').read_text()
assert 'wb_panel_cache mirror_cache;' in display and 'f->mirror_cache.valid=false;' in display
with tempfile.TemporaryDirectory() as tmp:
 d=Path(tmp);(d/'dispatch.inc').write_text(s[a:b],encoding='utf8');exe=d/'controls.exe'
 subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(SRC),'-I'+str(HERE.parent/'stub'),'-I'+str(d),str(HERE/'probe.c'),str(SRC/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
 subprocess.run([exe],check=True)
