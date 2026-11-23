from pathlib import Path
import tempfile,subprocess,shutil
H=Path(__file__).resolve().parent
S=H.parents[1]/"source"
def build(t,adapter=None):
    t.mkdir(exist_ok=True)
    if adapter is not None:shutil.copyfile(adapter,t/'wb_tty_vita.inc')
    p=t/"adapter.exe"
    subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror","-I"+str(t),"-I"+str(S),str(H/"probe.c"),str(S/"wb_sha256.c"),str(S/"wb_str.c"),str(S/"wb_path.c"),"-o",str(p)],check=True)
    return p
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:
        subprocess.run([str(build(Path(t)))],check=True,timeout=12)
