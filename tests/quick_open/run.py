"""Zero-X / guarded fallback. No physical device or network; require a host C compiler."""
from pathlib import Path
import os,subprocess,tempfile,sys
here=Path(__file__).resolve().parent
src=here.parents[1]/'source'
core=(src/'vita_ssh_status.c').read_text(encoding='utf8')
b=core.index('static char pw_diag_source[');end=core.index('/* ---- network ---- */',b)
assert 'const bool hands_free = true;' in core  # 02.18: paired listener never waits for a button
assert 'SQUARE OPENS PAIRED SSH' not in core and 'PAIRED OPEN NOT CONFIRMED' not in core
assert 'await_choice("CHECK MAC PUBLIC PIN"' not in core  # host key / owner pin never shown on the Vita
assert 'initial_power_drain(registration,hands_free,true,false,true)' in core
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)
    (p/'drain.inc').write_bytes(core[b:end].encode())
    exe=p/('guard.exe' if os.name=='nt' else 'guard')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I',str(src),'-I',str(p),str(here/'fixture.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
    for mode in ('healthy','focus','power','suspend','low'):
        subprocess.run([str(exe),'paired-auto-'+mode],cwd=p,check=True)
