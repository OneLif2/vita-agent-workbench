from pathlib import Path
import hashlib, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]; HERE=Path(__file__).resolve().parent
def main():
    with tempfile.TemporaryDirectory() as t:
        d=Path(t);ex=d/'atlas.exe';lic=d/'license.txt'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'source'),str(HERE/'probe.c'),'-o',str(ex)],check=True,timeout=30)
        subprocess.run([ex,lic],check=True,timeout=10)
        upstream=(ROOT/'tools/font_assets/OFL.txt').read_bytes()
        assert hashlib.sha256(upstream).hexdigest()=='30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad'
        assert lic.read_bytes()==upstream
        print('PASS compiled license byte-exact with immutable upstream OFL')
if __name__=='__main__':main()
