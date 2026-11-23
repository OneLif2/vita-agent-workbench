"""Host-only copied-header transaction; never contacts the Vita or Jetson."""
from pathlib import Path
import datetime as dt
import difflib
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile

D=Path(__file__).resolve().parent
T=D/'transaction'
R=D.parents[1]
P=R.parent/'v2.05/source/wb_app_running_vita.h'
C=R/'source/wb_app_running_vita.h'
ORIGINAL='014bec03029064b92f1086d00d324200bfc35e6b42f17d957907b47bbc7f9712'
spec=importlib.util.spec_from_file_location('safe_app_running_runner',D/'run.py')
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def command(args):
    args=[str(x) for x in args]
    q=subprocess.run(args,capture_output=True,text=True)
    return dict(command=args,stdout=q.stdout,stderr=q.stderr,exit_status=q.returncode)

def main():
    before=P.read_bytes();candidate=C.read_bytes()
    assert hashlib.sha256(before).hexdigest()==ORIGINAL
    assert (T/'BASELINE_FILE.h').read_bytes()==before and before.split()!=candidate.split()
    candidate_sha=hashlib.sha256(candidate).hexdigest()
    modified=T/'MODIFIED_FILE.h';modified.write_bytes(candidate)
    patch=T/'DIFF_FILE.patch'
    patch.write_bytes(''.join(difflib.unified_diff(before.decode().splitlines(True),candidate.decode().splitlines(True),fromfile='a/wb_app_running_vita.h',tofile='b/wb_app_running_vita.h')).encode())
    rollback=T/'ROLLBACK.sh'
    body='''#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] || { echo 'expected one regular target copy' >&2; exit 2; }
[ ! "$1" -ef "$0" ] || exit 2
dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
base="$dir/BASELINE_FILE.h"
[ -f "$base" ] && [ ! -L "$base" ] && [ ! "$1" -ef "$base" ] || exit 2
[ "$(wc -c < "$base" | tr -d '[:space:]')" = "NBYTES" ] || exit 2
tmp="$1.rollback.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
(set -C; cat "$base" > "$tmp") || exit 2
[ "$(wc -c < "$tmp" | tr -d '[:space:]')" = "NBYTES" ] || exit 2
cmp "$base" "$tmp" >/dev/null || exit 2
mv -f "$tmp" "$1"
trap - EXIT HUP INT TERM
printf 'restored pristine baseline bytes=NBYTES\n'
'''.replace('NBYTES',str(len(before)))
    rollback.write_bytes(body.encode());os.chmod(rollback,0o755)
    builds=[];rows={}
    cases=['positive','not-found','unknown','zero-pid','negative-pid','list-denied']
    with tempfile.TemporaryDirectory(prefix='app-running-0206-transaction-') as temp:
        temp=Path(temp)
        for role,header in [('BASELINE',T/'BASELINE_FILE.h'),('MODIFIED',modified)]:
            exe=runner.build(temp/role,header=header)
            builds.append(dict(role=role,header_sha256=sha(header),**runner.LAST_BUILD));rows[role]=[]
            for case in cases:
                row=dict(input=case,**command([exe,'--fixture',case]));rows[role].append(row)
                assert row['exit_status']==(0 if case=='positive' else 1) and not row['stderr'],row
            if role=='MODIFIED':
                suite=command([exe]);assert suite['exit_status']==0 and not suite['stderr'] and 'PASS TOTAL 78' in suite['stdout']
        for case in ['positive','not-found','unknown']:
            old=next(x for x in rows['BASELINE'] if x['input']==case);new=next(x for x in rows['MODIFIED'] if x['input']==case)
            assert (old['stdout'],old['stderr'],old['exit_status'])==(new['stdout'],new['stderr'],new['exit_status'])
        for case in ['zero-pid','negative-pid']:
            old=next(x for x in rows['BASELINE'] if x['input']==case);new=next(x for x in rows['MODIFIED'] if x['input']==case)
            assert 'state=not-started' in old['stdout'] and 'state=unknown' in new['stdout'] and 'symbol=INVALID_RESULT' in new['stdout']
        old=next(x for x in rows['BASELINE'] if x['input']=='list-denied');new=next(x for x in rows['MODIFIED'] if x['input']=='list-denied')
        assert 'unsafe_calls=6' in old['stdout'] and 'unsafe_calls=0' in new['stdout']
        assert 'not-probed reason=abi-unverified' in new['stdout'] and 'symbol=unknown' in new['stdout']
        reconstructed=temp/'reconstructed.h'
        rebuilt=command([r'C:\Program Files\Git\usr\bin\patch.exe','--binary','--batch','--silent','--output',reconstructed,T/'BASELINE_FILE.h',patch])
        assert rebuilt['exit_status']==0 and sha(reconstructed)==candidate_sha,rebuilt
        restored=temp/'restored-copy.h';restored.write_bytes(candidate)
        rolled=command([r'C:\Program Files\Git\bin\bash.exe',rollback.as_posix(),restored.as_posix()])
        assert rolled['exit_status']==0 and sha(restored)==ORIGINAL,rolled
        executable=command([r'C:\Program Files\Git\bin\bash.exe','-c','test -x "$1"','--',rollback.as_posix()]);assert executable['exit_status']==0
        exe=runner.build(temp/'ROLLBACK',header=restored);builds.append(dict(role='ROLLBACK',header_sha256=sha(restored),**runner.LAST_BUILD));rows['ROLLBACK']=[]
        for case in cases:
            row=dict(input=case,**command([exe,'--fixture',case]));rows['ROLLBACK'].append(row);old=next(x for x in rows['BASELINE'] if x['input']==case)
            assert (row['stdout'],row['stderr'],row['exit_status'])==(old['stdout'],old['stderr'],old['exit_status'])
        modified.write_bytes(reconstructed.read_bytes())
    assert C.read_bytes()==candidate and P.read_bytes()==before and sha(modified)==candidate_sha
    assert b'_sceAppMgrGetStatusByName(' not in candidate and b'_sceAppMgrGetPidListForShell(' not in candidate
    assert b'wb_running_fn(' not in candidate and b'wb_appinfo3_fn' not in candidate
    record=dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(),result='HOST_ONLY_SAFE_APP_RUNNING_0206_PASS',
        parent=dict(path=str(P),sha256=ORIGINAL),source=dict(path=str(C),sha256=sha(C)),
        changed_symbols=['wb_running_diagnose','wb_running_admission','wb_running_query_state','wb_running_title_query'],
        scope='Copied v2.06 host candidate only; no Vita/Jetson/build release/install or permission changes',
        commands=rows,builds=builds,candidate_suite=suite,patch_reconstruction=rebuilt,rollback_execution=rolled,
        rollback_executable=executable,restored_sha256=ORIGINAL,goal_reapplied=True,parent_unchanged=True,
        preserved=['SDK ForShell raw rc','GetIdByName self diagnostic','paired owner PTY and descriptor guards','snapshot/PID/title rechecks','no foreground claim','NOT_FOUND-only absence'],
        limitations=['Legacy unsafe symbol fixtures exist only to compare the immutable parent, not to assert firmware ABIs.','No live running/game/foreground behavior accepted by these stubs.'],
        roles=[dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p)) for p in [modified,patch,rollback]])
    verification=T/'VERIFICATION.txt';verification.write_bytes((json.dumps(record,indent=2)+'\n').encode())
    (D/'HOST-TESTS.json').write_bytes((json.dumps(dict(utc=record['utc'],result=record['result'],candidate_suite=suite,transaction=str(verification),source_sha256=sha(C),parent_sha256=ORIGINAL),indent=2)+'\n').encode())
    roles=[dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p)) for p in [modified,patch,verification,rollback]]
    for row in roles:assert Path(row['path']).read_bytes()
    print(json.dumps(dict(result=record['result'],suite_checkpoints=78,roles=roles),indent=2))
if __name__=='__main__':main()
