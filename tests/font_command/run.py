"""Compile the actual PTY parser + persistent profile adapter against bounded fake storage."""
from pathlib import Path
import subprocess,tempfile
p=Path(__file__).resolve().parent;s=p.parents[1]/'source'
vita=(s/'vita_ssh_status.c').read_text()
a=vita.index('static wb_font_state font_state;')
# Extract only the actual font adapter. New sibling feature includes between
# this declaration and core_exec are not font dependencies or fixture stubs.
end='static const wb_font_storage font_storage={font_read,font_write};'
assert vita.count(end)==1
b=vita.index(end,a)+len(end)
assert '#include "wb_wake_probe_vita.h"' not in vita[a:b]
assert 'wb_font_boot(&font_state,&font_storage);' in vita and 'return wb_font_command(cmd,out,status,&font_state,&font_storage);' in vita
with tempfile.TemporaryDirectory() as td:
 d=Path(td);(d/'font_adapter.inc').write_text(vita[a:b],encoding='utf8')
 exe=d/'font-fixture.exe'
 subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(s),'-I'+str(d),str(p/'fixture.c'),
  *[str(s/(v+'.c')) for v in ('wb_cmd','wb_out','wb_str','wb_shell','wb_screen_mirror')],'-o',str(exe)],check=True)
 subprocess.run([exe],check=True)
