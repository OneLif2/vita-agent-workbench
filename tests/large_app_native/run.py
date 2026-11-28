"""Production protected-spool regression with disk-backed synthetic >192MiB input.
No sockets, Vita, install, owner key or live device state is used.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import shutil
D=Path(__file__).resolve().parent
ROOT=D.parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix='wb-protected-spool-') as tmp:
        base=Path(tmp);exe=base/('spool.exe' if os.name=='nt' else 'spool')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT/'source'),
                        str(D/'spool_fixture.c'),str(ROOT/'source/wb_sha256.c'),'-o',str(exe)],check=True)
        source=base/'input.bin';block=bytes(range(256))*256;size=193*1024*1024+17
        for scenario in ['original','tampered-spool','begin-fail','write-fail','finish-fail','cancel','dispose-fail','mutated-source']:
            # Recreate the same bytes after the source-mutation scenario too.
            h=hashlib.sha256()
            with source.open('wb') as file:
                left=size
                while left:
                    part=block[:min(left,len(block))];file.write(part);h.update(part);left-=len(part)
            subprocess.run([str(exe),scenario,str(source),str(size),h.hexdigest()],check=True,timeout=90)
        subprocess.run([sys.executable,'-B',str(ROOT/'tools/gen_app_registry.py'),str(base/'wb_registry_data.inc')],check=True)
        gate=base/('gate.exe' if os.name=='nt' else 'gate')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                        '-include',str(D/'tracked_alloc.h'),'-I'+str(base),'-I'+str(ROOT/'source'),'-I'+str(ROOT/'tests/stub'),
                        str(D/'gate_fixture.c'),*[str(ROOT/'source'/(name+'.c')) for name in
                        ('wb_zip','wb_inflate','wb_crc32','wb_sfo','wb_out','wb_str','wb_path','wb_sha256','wb_sha1','wb_head','wb_err')],
                        '-o',str(gate)],check=True)
        spec=importlib.util.spec_from_file_location('large_host_fixtures',ROOT/'tests/large_app_host/run.py')
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        package,_=fixtures.build(base)
        good_sha=fixtures.digest(package);size=package.stat().st_size
        for scenario in ['plan','install','spool-mutated-before-validate','spool-mutated-after-validate',
                         'snapshot-no-space','stage-no-space','sha-denied','title-denied','version-denied','cleanup-failed']:
            subprocess.run([str(gate),scenario,str(package),str(size),good_sha],check=True,timeout=90)
        damaged=base/'crc.vpk';shutil.copyfile(package,damaged)
        with damaged.open('r+b') as file:file.seek(65536+17);file.write(b'\xa7')
        subprocess.run([str(gate),'crc-bad',str(damaged),str(size),fixtures.digest(damaged)],check=True,timeout=90)
        subprocess.run([str(gate),'source-mutated',str(package),str(size),good_sha],check=True,timeout=90)
    print('HOST native protected-spool only: product copy/block-SHA reader, bounded tracked allocations and fault cleanup; not device acceptance')
if __name__=='__main__':main()
