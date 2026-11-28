"""Compile the production idle policy and actual Vita wrapper against SDK stubs.

No listener, device, network, UI automation or Vita power call is executed.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, default=ROOT / 'source' / 'vita_ssh_status.c')
p.add_argument('--include', type=Path, default=ROOT / 'source')
a = p.parse_args()


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout, end='')
    print(r.stderr, end='', file=__import__('sys').stderr)
    if r.returncode:
        raise SystemExit(r.returncode)
    assert not r.stderr


with tempfile.TemporaryDirectory(prefix='wb-idle-screen-') as tmp:
    d = Path(tmp)
    cc = shutil.which('gcc') or 'gcc'
    flags = [cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(a.include), '-I' + str(ROOT / 'tests' / 'stub')]
    exe = d / ('policy.exe' if os.name == 'nt' else 'policy')
    run(flags + [str(D / 'policy.c'), '-o', str(exe)])
    run([str(exe)])
    # The runner extracts the actual adapter rather than a hand-reimplemented
    # idle algorithm. Extraction boundaries are checked below once per run.
    source = a.source.read_text(encoding='utf-8')
    start = source.index('/* Display idleness is independent')
    end = source.index('int main(void)', start)
    adapter = source[start:end]
    assert 'static void idle_screen_poll(' in adapter
    c = d / 'native.c'
    check = re.search(r'(?m)^        if \(!input && !a.remote_start[^\n]+', source).group(0)
    check = check.replace('reason = "LOCAL INPUT ERROR"; break;', 'return false;')
    assert 'idle_screen.off' in check
    assert source.index('idle_screen_poll(mono,input,&pad);', end) < source.index('if (!input && !a.remote_start', end)
    fixture = (D / 'native.c.in').read_text(encoding='utf-8')
    fixture = fixture.replace('ACTUAL_IDLE_ADAPTER', adapter).replace('ACTUAL_INPUT_ERROR_CHECK', check)
    c.write_text(fixture, encoding='utf-8')
    exe = d / ('native.exe' if os.name == 'nt' else 'native')
    run(flags + [str(c), '-o', str(exe)])
    run([str(exe)])
    transport = (a.source.parent / 'wb_ssh.c').read_text(encoding='utf-8')
    keep = transport[transport.index('static bool interactive_idle_keep('):transport.index('int wb_ssh_service(')]
    before = transport.index('    if (!s->kex && t >= s->kex_deadline)', transport.index('int wb_ssh_service('))
    after = transport.index('    if (!s->kex) {', before)
    checks = transport[before:after]
    assert 'interactive_idle_keep(s)' in checks
    fixture = (D / 'transport.c.in').read_text(encoding='utf-8')
    fixture = fixture.replace('ACTUAL_INTERACTIVE_KEEP', keep).replace('ACTUAL_DEADLINE_CHECKS', checks)
    c = d / 'transport.c'
    c.write_text(fixture, encoding='utf-8')
    exe = d / ('transport.exe' if os.name == 'nt' else 'transport')
    run(flags + [str(c), '-o', str(exe)])
    run([str(exe)])
