"""Focused 01.77 regression; no device, live key, or system configuration access."""
from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys

root = Path(__file__).resolve().parents[1]
cases = [
    ('owner_pin', ['../v1.77/core-candidate/tests/run_probe.py', 'source/vita_ssh_status.c']),
    ('quick_open', ['tests/quick_open/run.py']),
    ('terminal_auth_and_display', ['tests/terminal_flow/run.py']),
    ('sftp_auth_gate', ['tests/sftp_admission/run.py', '--source', 'source']),
    ('wbq2', ['tests/s1/run.py']),
    ('dispatch', ['tests/dispatch/run.py', 'source/vita_ssh_status.c']),
    ('r1_return', ['tests/return_core/run.py']),
    ('updater_return', ['tests/return_updater/run.py']),
    ('power_ux', ['tests/startup_power_ux/run.py']),
    ('shell', ['tests/shell_engine/run.py']),
    ('updater_layout_status', ['tests/settings_folder/run.py']),
    ('updater_reuse', ['tests/updater_reuse/run.py']),
]
def main():
    report = {'scope':'host fixtures, no device', 'core_source_sha256': hashlib.sha256((root/'source/vita_ssh_status.c').read_bytes()).hexdigest(), 'suites':[]}
    for name, args in cases:
        argv = [sys.executable, '-B', *args]
        p = subprocess.run(argv, cwd=root, capture_output=True, timeout=90,
                           env=dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1'))
        report['suites'].append(dict(name=name, argv=argv, exit=p.returncode,
            stdout=p.stdout.decode('utf-8','replace'), stderr=p.stderr.decode('utf-8','replace')))
        print(name, p.returncode, flush=True)
    report['passed'] = all(r['exit']==0 for r in report['suites'])
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    name=root/'evidence'/('HOST-PIN-RC-'+suffix+'.json')
    with name.open('x',encoding='utf-8') as f:
        json.dump(report,f,indent=2); f.write('\n')
    print(name)
    return not report['passed']
if __name__=='__main__': sys.exit(main())
