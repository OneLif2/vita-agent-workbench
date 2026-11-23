"""Compile actual bridge and shell against deterministic native SDK stubs.

The production bridge is copied byte-for-byte except its generated approval
include is redirected to tiny four-member fixtures. This is NOT package
approval/installation evidence. Production VPK metadata is audited separately.
"""
from pathlib import Path
import hashlib, json, os, subprocess, tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
S=ROOT/'source'
BLOBS=[b'approved frontend',b'approved worker',b'frontend SFO 01.02',b'worker SFO 01.02']
PATHS=['eboot.bin','eboot2.bin','sce_sys/param.sfo','sce_sys/param2.sfo']

def approval():
    arrays='\n'.join('static const unsigned char fixture_blob_%d[]={%s};'%(i,','.join(str(x) for x in b)) for i,b in enumerate(BLOBS))
    return '''#ifndef FIXTURE_APPROVAL_H
#define FIXTURE_APPROVAL_H
#define FIXTURE_VPK_SHA "%s"
#define WB_PROBE_TITLE "WBLC00079"
#define WB_PROBE_VERSION "01.02"
#define WB_PROBE_VPK_SHA256 FIXTURE_VPK_SHA
%s
static const unsigned char *fixture_blobs[]={%s};
static const size_t fixture_sizes[]={%s};
static const char *fixture_paths[]={%s};
static const struct{const char*path;size_t bytes;const char*sha256;}wb_probe_members[]={%s};
#endif
'''%('1'*64,arrays,','.join('fixture_blob_%d'%i for i in range(4)),','.join(str(len(x)) for x in BLOBS),','.join(json.dumps(x) for x in PATHS),','.join('{%s,%d,%s}'%(json.dumps(p),len(b),json.dumps(hashlib.sha256(b).hexdigest())) for p,b in zip(PATHS,BLOBS)))

def build(t,shell=None):
    t.mkdir(exist_ok=True)
    (t/'source').mkdir(exist_ok=True)
    (t/'wake-probe').mkdir(exist_ok=True)
    bridge=(S/'wb_wake_probe_vita.h').read_text(encoding='utf8')
    needle='#include "wb_wake_probe_approved.h"'
    assert bridge.count(needle)==1
    (t/'source/wb_wake_probe_vita.h').write_text(bridge.replace(needle,'#include "fixture_approval.h"'),encoding='utf8')
    (t/'wake-probe/wake_probe_protocol.h').write_bytes((ROOT/'wake-probe/wake_probe_protocol.h').read_bytes())
    (t/'source/fixture_approval.h').write_text(approval(),encoding='utf8')
    main=(S/'vita_ssh_status.c').read_text(encoding='utf8')
    a=main.index('        case WB_CMD_TERM_CLOSE_WB:')
    (t/'close.inc').write_text(main[a:main.index('        case WB_CMD_TERM_R1_REVIEW:',a)],encoding='utf8')
    exe=t/('native.exe' if os.name=='nt' else 'native')
    cmd=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-I'+str(t/'source'),'-I'+str(t),'-I'+str(S),str(D/'native.c'),str(shell or S/'wb_shell.c'),*(str(S/(n+'.c')) for n in ('wb_cmd','wb_str','wb_out','wb_err','wb_sha256')),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    return exe

if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='wb-wake-probe-') as temp:
        subprocess.run([str(build(Path(temp)))],check=True)
