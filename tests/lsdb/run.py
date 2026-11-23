"""Replay the negative control signature from the physical 01.71 precheck in the integrated native code. Offline only."""
from pathlib import Path
import hashlib, json, subprocess, sys

HERE = Path(__file__).resolve().parent
RAW = (HERE / 'observed-0171.json').read_bytes()
if hashlib.sha256(RAW).hexdigest() != 'c338bcf42d884f2396e11bbedf0612d601ab15dce4b3896bf6da1efa49a8b340':
    raise ValueError('archived 01.71 evidence digest differs')
events = json.loads(RAW)['events']
assert events[0]['identity']['run'] == 'F2CBE1E7394A4381'
status = [entry['stdout'] for entry in events if entry['command'] == 'app status VSSH00001']
assert status == [['ERR app-uninstall-gate phase=db-absent-control rc=80101005 value=00000003 disk=00000000 issued=0']]
assert not any(entry['command'] == 'app uninstall VSSH00001' for entry in events)
runner = HERE.parent / 'ssh_vita_uninstall' / 'run.py'
def exercise(*opts):
    return subprocess.check_output([sys.executable, '-B', str(runner), *opts], text=True).splitlines()

trace = exercise('--observe-hardware-signature')
expected = [
    'before: app title=VSSH00001 state=installed app_ver=01.42',
    'delete: OK app-uninstall title=VSSH00001 state=absent',
    'after: app title=VSSH00001 state=absent',
    'fixture native delete calls=1 disk=0 registry=0',
]
if trace != expected:
    raise ValueError(f'unexpected stub transitions: {trace!r}')
negative = exercise()
assert any('reject 255 same-family LSDB negatives' in line and '7 nonmatching out-words' in line for line in negative)
print('PASS lsdb: archived physical 01.71 refused rc=80101005 value=3 issued=0; integrated native 01.72 stub accepts only that additional tuple.')
print(*trace, sep='\n')
print('PASS lsdb negatives: controls and target reject 255 neighbouring codes and seven wrong out-words; no device action.')
