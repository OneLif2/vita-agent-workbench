"""Compile actual local-only enrollment/storage code against capture-only stubs.

No device, sockets, remote command, physical input or native savedata is used.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, default=ROOT / 'source' / 'wb_standing_vita.h')
p.add_argument('--core', type=Path, default=ROOT / 'source' / 'vita_ssh_status.c')
a = p.parse_args()
source = a.source.read_text(encoding='utf-8')
assert 'static bool wb_standing_reenroll_local(' in source
# Keep the real record schema, native SaveData/readback, active-record validator,
# unchanged historical bootstrap and new local enrollment. Extract the actual
# bounded focus-settle functions from the remaining header separately; the
# unrelated SSH signed-grant bracket has its own native coverage.
prefix = source[:source.index('/* Local SELECT only.')]
def function(signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1]
    raise ValueError('Unclosed actual function: ' + signature)

enum_start = source.index('enum { WB_FOCUS_SETTLE_MS=')
settle = source[enum_start:source.index('};', enum_start) + 2] + '\n'
settle += '\n'.join(function(s) for s in (
    'static void wb_focus_note(',
    'static bool wb_focus_power_benign(',
    'static bool wb_standing_focus_settle(uint32_t *generation) {',
))
with tempfile.TemporaryDirectory(prefix='wb-standing-enroll-') as td:
    d = Path(td)
    (d / 'standing_under_test.inc').write_text(prefix + '\n#endif\n', encoding='utf-8')
    (d / 'settle_under_test.inc').write_text(settle, encoding='utf-8')
    c = d / 'native.c'
    c.write_text((D / 'native.c.in').read_text(encoding='utf-8'), encoding='utf-8')
    exe = d / ('native.exe' if os.name == 'nt' else 'native')
    commands = [[shutil.which('gcc') or 'gcc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-function', '-Wno-unused-variable', '-DWB_STANDING_BOOTSTRAP=0',
                 '-I' + str(a.source.parent), '-I' + str(ROOT / 'source'), '-I' + str(ROOT / 'tests' / 'stub'), '-I' + str(d),
                 str(c), '-o', str(exe)], [str(exe)]]
    for cmd in commands:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(r.stdout, end='')
        print(r.stderr, end='', file=__import__('sys').stderr)
        if r.returncode:
            raise SystemExit(r.returncode)
        assert not r.stderr
    # Compile actual main reopen blocks: no marker may consume 02.08's return
    # before the separate physical consent, nor reexec after refused consent.
    core = a.core.read_text(encoding='utf-8')
    def block(signature):
        start = core.index(signature); opening = core.index('{', start); depth = 1
        for end in range(opening + 1, len(core)):
            depth += (core[end] == '{') - (core[end] == '}')
            if not depth:
                return core[start:end + 1]
        raise ValueError('Unclosed main block: ' + signature)
    early = block('if(wb_reopen_requested() && strcmp(WB_VERSION,"02.08"))')
    late = block('if(standing_ready && wb_reopen_requested())')
    call = 'const bool standing_ready=wb_standing_reenroll_local(&ret);'
    assert core.index('r1_completed=ret;r1_bound=true;') < core.index('wb_standing_bootstrap(&ret);') < core.index(call) < core.index(late)
    assert core.index(early) < core.index(call)
    assert core.count('wb_standing_reenroll_local(&ret)') == 1
    c = d / 'reopen.c'
    fixture = (D / 'reopen.c.in').read_text(encoding='utf-8')
    c.write_text(fixture.replace('ACTUAL_EARLY_REOPEN', early).replace('ACTUAL_ENROLL_CALL', call).replace('ACTUAL_POST_ENROLL_REOPEN', late), encoding='utf-8')
    exe = d / ('reopen.exe' if os.name == 'nt' else 'reopen')
    commands = [[shutil.which('gcc') or 'gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], [str(exe)]]
    for cmd in commands:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(r.stdout, end='');print(r.stderr, end='', file=__import__('sys').stderr)
        if r.returncode:
            raise SystemExit(r.returncode)
        assert not r.stderr
