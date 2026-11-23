"""01.91: compile the SHIPPING wb_wake_probe_vita.h against bounded SDK fixtures.

The header under test is the production file, so this suite fails if the
merged publish-diagnostic work is removed or drifts. Two parts:

1. the original 97-case suite must still print `PASS TOTAL 97`;
2. the 25 targeted fault cases must each report the FIRST failed phase /
   operation / raw rc / rc kind, keep the fixture side effects unchanged, and
   never launch anything.

Only the generated approved-members include is redirected to four tiny blobs.
No Vita, socket, savedata or real launch exists in this fixture.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
S=ROOT/'source'
TARGET=S/'wb_wake_probe_vita.h'
# The exact shipping diagnostic header this suite is pinned to.
SHIPPING_SHA='c6189070b04fe34e8aafd41dc678ef7741f550c245957b8bcf66fe341da96cc9'
spec=importlib.util.spec_from_file_location('approved_fixture_inputs',ROOT/'tests/wake_probe/run.py')
prior=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)

EXPECTED={
 'installed-recheck':('installed-recheck','member-open',-2,'wb',0),
 'clock-rtc':('publish-clock','rtc',-701,'native',-1),
 'clock-expired':('publish-live','deadline',-14,'predicate',-1),
 'open':('public-open','open',-711,'native',-1),
 'write':('public-write','write',-721,'native-return',-1),
 'write-zero':('public-write','write-zero',0,'native-return',-1),
 'sync':('public-sync','sync',-725,'native',-1),
 'close':('public-close','close',-731,'native',-1),
 'readback-stat':('public-readback','stat',-741,'native',-1),
 'readback-open':('public-readback','open',-742,'native',-1),
 'readback-read':('public-readback','read',-743,'native-return',-1),
 'readback-trailing':('public-readback','trailing-read',-744,'native-return',-1),
 'readback-close':('public-readback','close',-745,'native',-1),
 'readback-size':('public-readback','size',-17,'predicate',-1),
 'readback-content':('public-readback','content',-8,'predicate',-1),
 'rename':('public-rename','rename',-749,'native',-1),
 'rename-collision':('public-rename','job-exists',1,'exists-helper',-1),
 'postverify-stat':('public-postverify','stat',-751,'native',-1),
 'postverify-content':('public-postverify','content',-8,'predicate',-1),
 'final-installed':('final-installed','member-open',-2,'wb',0),
 'final-clock-rtc':('final-clock','rtc',-701,'native',-1),
 'final-clock-expired':('final-live','deadline',-14,'predicate',-1),
 'write-first-error':('public-write','write',-721,'native-return',-1),
 'sync-first-error':('public-sync','sync',-725,'native',-1),
 'close-cleanup-failure':('public-close','close',-731,'native',-1),
}


def build(header,directory):
    directory=Path(directory)
    (directory/'source').mkdir(parents=True)
    (directory/'wake-probe').mkdir()
    blob=Path(header).read_bytes()
    needle=b'#include "wb_wake_probe_approved.h"'
    assert blob.count(needle)==1
    (directory/'source/wb_wake_probe_vita.h').write_bytes(blob.replace(needle,b'#include "fixture_approval.h"'))
    (directory/'wake-probe/wake_probe_protocol.h').write_bytes((ROOT/'wake-probe/wake_probe_protocol.h').read_bytes())
    (directory/'source/fixture_approval.h').write_text(prior.approval(),encoding='utf-8')
    main=(S/'vita_ssh_status.c').read_text(encoding='utf-8')
    start=main.index('        case WB_CMD_TERM_CLOSE_WB:')
    end=main.index('        case WB_CMD_TERM_R1_REVIEW:',start)
    (directory/'close.inc').write_text(main[start:end],encoding='utf-8')
    exe=directory/('native.exe' if os.name=='nt' else 'native')
    command=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror',
        '-I'+str(directory/'source'),'-I'+str(directory),'-I'+str(S),str(D/'native.c'),
        *(str(S/(name+'.c')) for name in ['wb_shell','wb_cmd','wb_str','wb_out','wb_err','wb_sha256']),
        '-o',str(exe)]
    compiled=subprocess.run(command,capture_output=True,text=True)
    if compiled.returncode:
        sys.stderr.write(compiled.stdout+compiled.stderr)
        raise RuntimeError('shipping header host compilation failed')
    return exe


def execute(exe,case=None):
    return subprocess.run([str(exe)]+(['--fixture',case] if case else []),capture_output=True,text=True)


def main():
    shipping=TARGET.read_bytes()
    digest=hashlib.sha256(shipping).hexdigest()
    if digest!=SHIPPING_SHA:
        raise SystemExit(f'shipping diagnostic header drifted: {digest} != {SHIPPING_SHA}')
    with tempfile.TemporaryDirectory(prefix='wake-probe-diagnostic-') as temp:
        exe=build(TARGET,Path(temp))
        suite=execute(exe)
        assert suite.returncode==0 and 'PASS TOTAL 97' in suite.stdout,(suite.stdout,suite.stderr)
        print(suite.stdout.splitlines()[-1])
        for case,(phase,operation,rc,kind,member) in EXPECTED.items():
            row=execute(exe,case)
            literal=(f'ERR wake-probe phase={phase} op={operation} rc=0x{rc&0xffffffff:08X} '
                     f'rc_kind={kind} member={member}; WB not closed')
            assert row.returncode==1,(case,row.returncode,row.stdout,row.stderr)
            assert not row.stderr,(case,row.stderr)
            assert row.stdout.splitlines()[0]==literal,(case,row.stdout,literal)
            assert 'launches=0' in row.stdout,(case,row.stdout)
        print(f'PASS TOTAL {len(EXPECTED)} diagnostic fault cases name the first failed phase; launches=0')
    if TARGET.read_bytes()!=shipping:raise SystemExit('shipping header changed during the run')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
