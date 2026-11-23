"""Optional: compile both product engines and compare their pre-existing LIVE grid API."""
from pathlib import Path
import argparse,tempfile,subprocess
h=Path(__file__).resolve().parent;s=h.parents[1]/'source'
p=argparse.ArgumentParser();p.add_argument('--baseline',required=True,type=Path);a=p.parse_args()
with tempfile.TemporaryDirectory() as tmp:
    streams=[]
    for ix,src in enumerate([a.baseline.resolve(),s]):
        exe=Path(tmp)/f'live{ix}.exe'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(src),str(h/'differential.c'),str(src/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
        output=subprocess.check_output([str(exe)],text=True);streams.append(output);print(src,output,end='')
    assert streams[0]==streams[1]
    print('PASS: compared original and candidate live geometry/cursor/all live text after every operation; navigation adds no mutation to the SSH terminal model.')
