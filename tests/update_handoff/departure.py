"""Exercise the actual 01.71 and candidate apply tail + run loop exit block with stub OS calls."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
candidate = here.parents[1]
records = []
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    for root, old in [(candidate.parent / 'v1.71', True), (candidate, False)]:
        src = root / 'source'
        core = (src / 'vita_ssh_status.c').read_text()
        trans = (src / 'wb_ssh.c').read_text()
        begin = core.index('            int detail = 0;', core.index('case WB_CMD_APPLY_CORE:'))
        pos = core.index('            (void)wb_out_printf(out, "OK updater installed' if old
                         else '            a.guard_grace = now_ms()', begin)
        # New unrelated typed commands follow the apply group; legacy sources
        # transition directly to BYE. Keep the exact apply-case closing boundary.
        following = ('WB_CMD_TERM_APP_RUNNING' if '        case WB_CMD_TERM_APP_RUNNING:' in core[pos:]
                     else 'WB_CMD_BYE')
        end = '\n        }\n        case '+following+':'
        assert core.count(end)==1
        tail = core[pos:core.index(end,pos)]
        assert 'wb_app_running_command' not in tail and 'wb_probe_command' not in tail
        if old:
            assert 'sceKernelExitProcess(' not in core and 'wb_ssh_flush_handoff' not in core
        body = '' if old else core[core.index('        if (a.updater_accepted) {'):
                                   core.index('        if (!served)')]
        drain = '' if old else trans[trans.index('int wb_ssh_flush_handoff('):
                                      trans.index('/* Only the engine can supply')]
        f = (here / 'departure.c.in').read_text().replace('/* LAUNCH */', tail).replace(
            '/* DRAIN */', drain).replace('/* LOOP */', body)
        c = tmp / 'main.c'
        exe = tmp / ('main.exe' if os.name == 'nt' else 'main')
        c.write_text(f)
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-DOLD='+str(int(old)), '-I'+str(src), str(c),
                        *[str(src/(s+'.c')) for s in ('wb_shell_channel','wb_shell','wb_cmd','wb_out','wb_str')],
                        '-o', str(exe)], check=True)
        for mode in (('ok', 'negative', 'partial', 'backpressure', 'lost-peer', 'no-channel') + (() if old else ('reused',))):
            p = subprocess.run([str(exe), mode], capture_output=True, text=True)
            print(root.name, mode, p.stdout.strip(), flush=True)
            records.append(dict(version=root.name, mode=mode, rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
            if p.returncode:
                raise RuntimeError(p.stderr)
out = candidate / 'evidence' / 'host-voluntary-exit.json'
out.write_text(json.dumps(dict(scope='Host actual lifecycle and output buffering, not system UI or device proof',
                              cases=records),indent=2)+'\n',encoding='utf8')
