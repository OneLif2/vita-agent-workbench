"""Exercise real signed issue/dispatch with deterministic faults inside the queue hash."""
from pathlib import Path
import tempfile,subprocess,sys
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
sys.path.insert(0,str(ROOT/'tests/standing_native'))
from run import materialize as standing_materialize,build

def materialize(d):
    standing_materialize(d)
    file=d/'fixture.c';c=file.read_text(encoding='utf8')
    old='static int queued_core_check(void){return healthy_stage?WB_OK:WB_E_STATE;}'
    assert c.count(old)==1
    c=c.replace(old,'static int queued_core_check(void);')
    c=c.replace('static bool fail_save,', '#include "inject.inc"\nstatic bool fail_save,')
    c=c.replace('int main(void)', 'int other_main(void)')
    file.write_text(c+(D/'native.c.in').read_text(encoding='utf8'),encoding='utf8')
    (d/'inject.inc').write_bytes((D/'inject.c.in').read_bytes())
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:
        d=Path(t);materialize(d);subprocess.run([str(build(d))],check=True,cwd=d)
