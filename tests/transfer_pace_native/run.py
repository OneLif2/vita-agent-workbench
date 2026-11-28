"""Compile actual native fast-pump/UI functions with deterministic time/IO.
No network or Vita. Outer-loop security ordering is checked, not hardware-simulated.
"""
from pathlib import Path
import subprocess,tempfile,os
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
source=(ROOT/'source/vita_ssh_status.c').read_text(encoding='utf8')
start=source.index('static uint64_t xfer_t0,')
end=source.index('\n#endif\n\nint main(void)',start)
listener=source.index('unsigned ui_seen=0; /* per-listener')
pace=source.index('const int pace = wb_transfer_pace(',listener)
for guard in ('pad.buttons & SCE_CTRL_START','const bool guard_active',
              'if (a.updater_accepted)'):
    assert source.index(guard,listener)<pace,guard
assert 'if(r1_notice.pending)' not in source[pace:], '02.18 removed the R1 owner prompt from the listener loop'
with tempfile.TemporaryDirectory(prefix='wb-native-transfer-pace-') as tmp:
    p=Path(tmp);(p/'pace.inc').write_text(source[start:end],encoding='utf8')
    exe=p/('pace.exe' if os.name=='nt' else 'pace')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(p),'-I'+str(ROOT/'source'),str(D/'fixture.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=15)
print('PASS native outer-loop source ordering: START/SELECT/power/guard/updater exit before fast burst; notice deferred while active; no hardware assertion')
