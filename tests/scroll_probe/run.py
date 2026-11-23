"""Compile a fixed local measurement harness against a selected trusted native source tree; no network."""
import argparse, pathlib, re, subprocess, sys, tempfile
P=pathlib.Path(__file__).resolve().parent
def main():
    a=argparse.ArgumentParser();a.add_argument('--source',type=pathlib.Path,default=P.parents[1]/'source')
    o=a.parse_args();s=o.source.resolve()
    has_nav=bool(re.search(r'\bwb_mirror_scroll\s*\(', (s/'wb_screen_mirror.h').read_text()))
    with tempfile.TemporaryDirectory() as td:
        exe=pathlib.Path(td)/'pixelprobe.exe'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-DHAS_NAV_API='+str(int(has_nav)),
                       '-I'+str(s),str(P/'probe.c'),str(s/'wb_screen_mirror.c'),'-o',str(exe)], check=True,timeout=45)
        return subprocess.run([str(exe)],timeout=10).returncode
if __name__=='__main__':sys.exit(main())
