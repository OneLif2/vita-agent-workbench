"""Exercise production listener open, validated auth, close and actual presented-frame selection.
OS sockets, libssh responses and drawing are stubbed; this does not connect to a device.
"""
from pathlib import Path
import os, re, subprocess, tempfile

HERE=Path(__file__).resolve().parent
SRC=HERE.parents[1]/'source'

def function(source, name):
    match=re.search(r'(?m)^(?:static )?(?:bool|int|void) '+name+r'\([^\n]*\) \{',source)
    if match is None: raise Exception('missing '+name)
    depth=1
    for i in range(match.end(),len(source)):
        if source[i]=='{': depth+=1
        elif source[i]=='}': depth-=1
        if not depth:return source[match.start():i+1]
    raise ValueError(name)

with tempfile.TemporaryDirectory() as td:
    tmp=Path(td)
    source=(SRC/'wb_ssh.c').read_text(encoding='utf8')
    (tmp/'transport.inc').write_text('\n'.join(function(source,n) for n in
        ('wb_ssh_open','wb_ssh_end_session','wb_ssh_close_listener','wb_ssh_connected',
         'auth_reply','handle_auth')),encoding='utf8')
    screen=(SRC/'vita_ssh_status.c').read_text(encoding='utf8')
    before=screen.index('        if (!g_ssh.listening) { reason = "LISTENER CLOSED"; break; }')
    after=screen.index('        sceKernelDelayThread(16000);',before)
    (tmp/'frame_loop.inc').write_text(screen[before:after],encoding='utf8')
    exe=tmp/('flow.exe' if os.name=='nt' else 'flow')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(SRC),
        '-I'+str(HERE.parent/'stub'),'-I'+str(tmp),str(HERE/'trace.c'),
        str(SRC/'wb_str.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
