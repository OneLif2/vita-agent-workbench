"""Compile the actual Vita spool adapter AND Vita reader with mode-aware SDK calls.

--adapter PATH --probe runs the identical fixture against a pristine or rolled
back header. Hardware semantics are modeled, not measured; native close failure
uses an explicit error-after-FD-retirement model, not a real-device FD guarantee.
"""
from pathlib import Path
import argparse,os,shutil,subprocess,tempfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter',type=Path)
    parser.add_argument('--probe',action='store_true')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='wb-native-spool-mode-') as tmp:
        out=Path(tmp)
        if args.adapter:shutil.copyfile(args.adapter,out/'wb_app_spool_vita.h')
        exe=out/('spool.exe' if os.name=='nt' else 'spool')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',
            '-I'+str(out),'-I'+str(ROOT/'tests/stub'),'-I'+str(ROOT/'source'),
            str(HERE/'fixture.c'),str(ROOT/'source/wb_vita_io.c'),str(ROOT/'source/wb_sha256.c'),'-o',str(exe)],check=True)
        if args.probe:
            subprocess.run([str(exe),'--probe'],check=True);return
        cases=('success','one-collision','collisions','alloc-fail','mkdir-root-fail','mkdir-fail','open-fail',
               'source-read-fail','write-fail','zero-write','oversize-write','sync-fail',
               'close-reports-error','reopen-fail','seek-fail','readback-fail','remove-fail','rmdir-fail')
        for case in cases:subprocess.run([str(exe),case],check=True,timeout=20)
        print('HOST only:18 actual native-adapter/reader scenarios; SDK mode0006 enforced; no Vita or install; cleanup failures leave only owned scratch and remain errors')
if __name__=='__main__':main()
