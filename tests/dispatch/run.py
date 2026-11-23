"""Compile the exact production extension switch case, real parser and ABI.
Run with one argument: path to vita_ssh_status.c. Host-only, never uses SSH/IO.
"""
import argparse, pathlib, shutil, subprocess, sys, tempfile
here=pathlib.Path(__file__).resolve().parent
srcdir=here.parents[1]/'source'
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('source',type=pathlib.Path)
ap.add_argument('--cc',default='gcc')
a=ap.parse_args()
source=a.source.read_text(encoding='utf-8')
header='        case WB_CMD_EXT: {'
trailer='        default:\n            return wb_out_puts(out, "ERR bad-command\\n");'
if source.count(header)!=1 or source.count(trailer)!=1:sys.exit('expected unique production ext switch anchors')
case=source[source.index(header):source.index(trailer,source.index(header))]
if 't->dispatch(' not in case:sys.exit('expected real payload dispatch call')
cc=shutil.which(a.cc)
if not cc:sys.exit('host C compiler unavailable')
with tempfile.TemporaryDirectory(prefix='wb-argv-') as t:
    t=pathlib.Path(t)
    (t/'ext_path.inc').write_text(case,encoding='utf-8')
    exe=t/('fixture.exe' if sys.platform=='win32' else 'fixture')
    cmd=[cc,'-std=c11','-O1','-Wall','-Wextra','-Werror','-I',str(srcdir),'-I',str(t),
        str(here/'dispatch_fixture.c'),*(str(srcdir/(name+'.c')) for name in ('wb_cmd','wb_str','wb_payload','wb_out','wb_path')),'-o',str(exe)]
    c=subprocess.run(cmd)
    if c.returncode:sys.exit(c.returncode)
    sys.exit(subprocess.run([str(exe)]).returncode)
