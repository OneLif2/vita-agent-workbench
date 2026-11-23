"""Compile the actual production table helper AND its actual core dispatch case.

SDK/table fixtures only; no Vita/network/launch/FS/UI implementation.
--source is a full production vita_ssh_status.c; no rewritten table algorithm.
"""
from pathlib import Path
import argparse
import ast
import os
import subprocess
import tempfile
import re

D=Path(__file__).resolve().parent
R=D.parents[1]
S=R/'source'


def function_end(text,start):
    # The named function contains no braces in string literals; brace depth
    # yields exactly the actual definition, including newly added helpers.
    opened=text.index('{',start);depth=1;i=opened+1
    while depth:
        if text[i]=='{':depth+=1
        elif text[i]=='}':depth-=1
        i+=1
    return i


def build(destination,source):
    t=Path(destination);t.mkdir(parents=True,exist_ok=True);(t/'psp2').mkdir()
    # Reuse the declarations already used by the existing native module suite.
    tree=ast.parse((R/'tests/app_running/run.py').read_text(encoding='utf-8'))
    sdk=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str) and 'FIXTURE_APPMGR_H' in n.value)
    (t/'psp2/appmgr.h').write_text(sdk,encoding='utf-8')
    main=Path(source).read_text(encoding='utf-8')
    definition=main.rindex('static int wb_running_sweep(')
    helper=main.rfind('/* WB_APPROVED_TABLE_BEGIN */',0,definition)
    start=helper if helper>=0 else definition
    (t/'actual_sweep.inc').write_text(main[start:function_end(main,definition)],encoding='utf-8')
    start=main.index('        case WB_CMD_TERM_APP_RUNNING:')
    end=main.index('        case WB_CMD_TERM_WAKE_PROBE:',start)
    (t/'actual_dispatch.inc').write_text(main[start:end],encoding='utf-8')
    exe=t/('native.exe' if os.name=='nt' else 'native')
    cmd=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-I'+str(t),'-I'+str(S),str(D/'native.c'),
         *(str(S/(x+'.c')) for x in ['wb_shell','wb_cmd','wb_out','wb_str','wb_err']),'-o',str(exe)]
    q=subprocess.run(cmd,capture_output=True,text=True)
    if q.returncode:raise RuntimeError(q.stderr)
    return exe,dict(command=cmd,stdout=q.stdout,stderr=q.stderr,exit_status=q.returncode)


CASES=['positive','unknown','zero-pid','negative-pid','not-found','positive-rc',
       'duplicate','duplicate-same-version','conflict','compiled-duplicate','runtime-duplicate',
       'runtime-conflict','distinct','empty','runtime-only','local-overflow','compiled-overflow','combined-overflow',
       'invalid-title','null-title','invalid-version','invalid-sha','runtime-invalid',
       'race-count-overflow','race-content','race-count-shrink','race-owner-loss','race-connection-loss',
       'race-on-write','worst-metadata','worst-error-metadata','max-unique',
       'write-fail-first','write-fail-note','write-fail-summary','disconnected']
CASES += ['no-pty-'+str(k) for k in range(8)]+['flag-'+str(k) for k in range(8)]


def execute(exe,case):
    q=subprocess.run([str(exe),case],capture_output=True,text=True)
    return dict(command=[str(exe),case],input=case,stdout=q.stdout,stderr=q.stderr,exit_status=q.returncode)


def check_case(row):
    case=row['input'];text=row['stdout'];assert row['stderr']=='',(case,row)
    state=re.search(r'^STATE status=(-?\d+) core_rc=(-?\d+) calls=(\d+) writes=(\d+)$',text,re.M)
    assert state,(case,row)
    semantic,core,calls,writes=map(int,state.groups())
    wire=text[:state.start()].splitlines();queries=re.findall(r'^QUERY (\w{9})$',text,re.M)
    assert len(queries)==calls and len(set(queries))==calls,(case,row)
    assert all(len(line)<512 and all(32<=ord(c)<127 for c in line) for line in wire),(case,row)
    assert len(wire)<=31 and sum(len(x)+2 for x in wire)<=12288,(case,row)
    failures=['unknown','zero-pid','negative-pid','positive-rc','conflict','runtime-conflict','worst-error-metadata',
       'local-overflow','compiled-overflow','combined-overflow','invalid-title','null-title','invalid-version','invalid-sha',
       'runtime-invalid','race-count-overflow','race-content','race-count-shrink','race-owner-loss',
       'race-connection-loss','race-on-write','disconnected']
    failed=case in failures or case.startswith(('no-pty-','flag-','write-fail-'))
    assert semantic==(1 if failed else 0),(case,row)
    assert row['exit_status']==(2 if case.startswith('write-fail-') else semantic),(case,row)
    if case.startswith('write-fail-'):
        assert core<0 and 'app-running table' not in '\n'.join(wire),(case,row)
        return dict(case=case,passed=True,wire_lines=len(wire),max_wire_line=max(map(len,wire),default=0))
    assert core==0,(case,row)
    no_sdk=case.startswith(('flag-','no-pty-')) or case in ['local-overflow','compiled-overflow','combined-overflow','invalid-title',
       'null-title','invalid-version','invalid-sha','runtime-invalid','disconnected']
    if no_sdk:
        assert calls==0 and 'ERR ' in text and 'app-running table' not in text,(case,row)
    elif case.startswith('race-'):
        assert 'ERR ' in text and 'app-running table' not in text,(case,row)
        assert calls==(2 if case=='race-on-write' else 1),(case,row)
    else:
        assert 'scope=approved-titles' in text and 'approval-versions-only' in text and 'no-foreground-claim' in text,(case,row)
        summary=next(x for x in wire if x.startswith('app-running table '))
        if case in ['unknown','zero-pid','negative-pid','positive-rc','worst-error-metadata']:
            assert 'state=unknown pid=0' in text and 'not_started=0 unknown=1' in summary and 'partial=yes' in summary,(case,row)
            assert 'state=not-started' not in text,(case,row)
        elif case=='not-found':
            assert 'symbol=NOT_FOUND state=not-started pid=0' in text and 'not_started=1 unknown=0' in summary,(case,row)
        elif case=='empty':
            assert calls==0 and 'titles=0 started=0 not_started=0 unknown=0' in summary and 'partial=no' in summary,(case,row)
        else:
            expected=16 if case=='max-unique' else 2 if case=='distinct' else 1
            assert calls==expected and f'titles={expected} started={expected}' in summary,(case,row)
        if case in ['duplicate','duplicate-same-version','conflict']:
            version='01.01' if case!='duplicate' else '01.02'
            assert f'approvals=compiled:01.01,owner-signed:{version}' in text,(case,row)
        if case in ['conflict','runtime-conflict']:
            assert 'approval_conflict=yes' in text and 'approval_conflicts=1 partial=yes' in summary,(case,row)
        if case in ['worst-metadata','worst-error-metadata']:
            metadata=','.join([f'compiled:01.{k:02d}' for k in range(8)]+[f'owner-signed:02.{k:02d}' for k in range(8)])
            assert wire[0].endswith('approvals='+metadata) and 'approval_rows=16' in summary,(case,row)
        if case=='max-unique':
            assert len(wire)==18 and all(q!='INAP00018' for q in queries),(case,row)
    return dict(case=case,passed=True,wire_lines=len(wire),max_wire_line=max(map(len,wire),default=0))


def suite(exe):
    rows=[]
    for case in CASES:
        row=execute(exe,case);row['check']=check_case(row);rows.append(row)
    return rows


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    p.add_argument('--source',type=Path,default=S/'vita_ssh_status.c');p.add_argument('--case')
    a=p.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='wb-approved-table-') as td:
        exe,_=build(Path(td),a.source)
        if a.case is None:
            rows=suite(exe)
            for row in rows:print('PASS '+row['input'])
            print('PASS TOTAL %d actual production table/dispatcher cases; no Vita I/O'%len(rows))
            return 0
        c=subprocess.run([str(exe),a.case],capture_output=True,text=True)
        print(c.stdout,end='')
        if c.stderr:print(c.stderr,file=__import__('sys').stderr,end='')
        return c.returncode


if __name__=='__main__':raise SystemExit(main())
