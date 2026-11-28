"""Same-input actual-source transaction probe; compile-only SDK/transport stubs.

Accepts a pristine, changed or restored vita_ssh_status.c copy. It runs the
actual old OLED tick/auto-suspend guard or actual new idle adapter at t=0 and
t=900000, together with the supplied actual transport deadline checks. The
output is host-fixture behavior, never a live-device acceptance receipt.
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
p.add_argument('--source', type=Path, required=True)
p.add_argument('--include', type=Path, default=ROOT / 'source')
p.add_argument('--transport', type=Path, default=ROOT / 'source' / 'wb_ssh.c')
p.add_argument('--at-ms', type=int, default=900000)
a = p.parse_args()
assert a.at_ms == 900000, 'transaction input is fixed at the 15-minute boundary'
source = a.source.read_text(encoding='utf-8')
transport = a.transport.read_text(encoding='utf-8')


def braced(s, start):
    b = s.index('{', start)
    depth = 1
    for i in range(b + 1, len(s)):
        depth += (s[i] == '{') - (s[i] == '}')
        if depth == 0:
            return s[start:i + 1]
    raise ValueError('unterminated production block')


if 'static void idle_screen_poll(' in source:
    begin = source.index('/* Display idleness is independent')
    adapter = source[begin:source.index('int main(void)', begin)]
    tick = 'idle_screen_poll(mono,true,&pad);'
else:
    adapter = ''
    main = source[source.index('int main(void)'):]
    tick = re.search(r'(?m)^\s*\(void\)sceKernelPowerTick\(SCE_KERNEL_POWER_TICK_DISABLE_OLED_OFF\);', main).group(0)
    # This is the exact legacy listener mechanism, not a fictional idle policy.
    g = source.index('        const bool guard_active = ', source.index('int main(void)'))
    adapter_guard = source[g:source.index('\n', g)]
    g = source.index('        if (guard_active && a.resilient)', g)
    tick += '\n' + adapter_guard + '\n' + braced(source, g)

keep = ''
if 'static bool interactive_idle_keep(' in transport:
    start = transport.index('static bool interactive_idle_keep(')
    keep = braced(transport, start)
b = transport.index('    if (!s->kex && t >= s->kex_deadline)', transport.index('int wb_ssh_service('))
checks = transport[b:transport.index('    if (!s->kex) {', b)]
fixture = (D / 'behavior.c.in').read_text(encoding='utf-8')
fixture = fixture.replace('ACTUAL_IDLE_ADAPTER', adapter).replace('ACTUAL_SCREEN_TICK', tick)
fixture = fixture.replace('ACTUAL_INTERACTIVE_KEEP', keep).replace('ACTUAL_DEADLINE_CHECKS', checks)
with tempfile.TemporaryDirectory(prefix='wb-idle-behavior-') as td:
    d = Path(td)
    c = d / 'behavior.c'
    c.write_text(fixture, encoding='utf-8')
    exe = d / ('behavior.exe' if os.name == 'nt' else 'behavior')
    commands = [
        [shutil.which('gcc') or 'gcc', '-std=c11', '-Wall', '-Wextra', '-Werror',
         '-I' + str(a.include), '-I' + str(ROOT / 'tests' / 'stub'), str(c), '-o', str(exe)],
        [str(exe), str(a.at_ms)],
    ]
    for cmd in commands:
        r = subprocess.run(cmd, capture_output=True, text=True)
        print(r.stdout, end='')
        print(r.stderr, end='', file=__import__('sys').stderr)
        if r.returncode:
            raise SystemExit(r.returncode)
        assert not r.stderr
