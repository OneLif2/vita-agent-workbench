"""Native, deterministic WBQ2 seal/consumer fault injection. No device, no SSH.
 --source-dir permits identical input on a source snapshot. --observe prints observations
without interpreting legacy 01.33 generic errors as successfully diagnosed.
"""
import argparse,hashlib,json,os,re,subprocess,sys,tempfile,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
R=HERE.parents[1];S=R/'source'
SFO=R.parent/'v1.33/build/workbench_0133.vpk'
PIN='9008ce18a1caa99a880687d49febe586abc4dc767f4bfd7cdf5cf4314958b1e3'
def h(b):return hashlib.sha256(b).hexdigest()
def build(s,t,cc,calibrate):
    # Adapter declarations map ux0:... file operations into a fresh temporary directory.
    raw=(R/'tests/s1/host.c').read_text(encoding='utf8').split('static wb_vfile vf;',1)[0]
    raw=re.sub(r'^#include "wb[^"]*"\s*$', '', raw, flags=re.M)
    raw=re.sub(r'\bsceIo([A-Za-z]+)\b',r'raw_sceIo\1',raw)
    (t/'adapter.inc').write_text(raw,encoding='utf8')
    hdr=(s/'wbq_io.h').read_text(encoding='utf8')
    core=(s/'vita_ssh_status.c').read_text(encoding='utf8')
    seal=core[core.index('static int seal_core_stage('):core.index('static int reset_queued_stage(')]
    trace='wq_seal(' in hdr
    if trace:
        assert 'wq_seal(' in seal or 'wq_seal(' in core, 'production core not wired to tested seal'
        inc='static int production_seal(const char *receipt){return wq_seal(WB_STAGE_DIR,WBQ_STORE,WBQ_SEAL,WB_PENDING_PATH,receipt,"01.32");}'
    else:
        inc='static bool new_seal;\n'+seal+'\nstatic int production_seal(const char *receipt){return seal_core_stage(NULL,receipt,"01.32");}'
    (t/'production.inc').write_text(inc,encoding='utf8')
    x=t/('fixture.exe' if os.name=='nt' else 'fixture')
    cmd=[cc,'-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
         '-DHAS_TRACE='+str(int(trace)),'-DWBQ_LEGACY_PROBE='+str(int(calibrate)), '-I'+str(s),'-I'+str(t),'-idirafter',str(R/'tests/stub'),
         str(HERE/'trace.c'),str(s/'wb_sha256.c'),str(s/'wb_sfo.c'),str(s/'wb_err.c'),'-o',str(x)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return x,trace,cmd
paths={'tree':'ux0:data/INAP00018/stage/pkg','sfo':'ux0:data/INAP00018/stage/pkg/sce_sys/param.sfo',
 'eboot':'ux0:data/INAP00018/stage/pkg/eboot.bin','store':'ux0:data/INAP00019',
 'private':'ux0:data/INAP00019/sealed-core.txt','public':'ux0:data/INAP00018/pending-core.txt','none':'-'}
# kind / injected operating-system operation / fixture target / expected rejection stage
cases=[('good','none','none','success'),('digest','none','none','seal'),('missing','none','none','seal'),
 ('extra','none','none','seal'),('legacy','none','none','final'),('private-mismatch','none','none','final'),('late-change','none','none','final')]
for op,p in [('dopen','tree'),('dread','tree'),('dclose','tree'),('open-read','sfo'),('read','sfo'),('close','sfo'),('open-read','eboot'),('read','eboot'),('close','eboot'),('mkdir','store')]:
 cases.append(('os-error',op,p,'seal'))
for p in ('private','public'):
 for op in ('open-write','write','zero-write','sync','close'):cases.append(('os-error',op,p,'seal'))
 cases.append(('partial-write','short-write',p,'success'))
def prepare(d,sfo):
    stage=d/'ux0_data/INAP00018/stage/pkg'
    (stage/'sce_sys/package').mkdir(parents=True)
    for n,b in [('eboot.bin',b'non-executable test core'),('sce_sys/param.sfo',sfo),('sce_sys/package/head.bin',b'inert head'),('workbench_payload.suprx',b'fixture (non-executable)')]:
        (stage/n).write_bytes(b)
def run(src,out=None,observe=False,calibrate=False):
    assert h(SFO.read_bytes())==PIN
    with zipfile.ZipFile(SFO) as z:sfo=z.read('sce_sys/param.sfo')
    with tempfile.TemporaryDirectory(prefix='wq-diagnostic-') as tt:
        td=Path(tt)
        x,trace,cmd=build(src,td,'gcc',calibrate)
        cases_here=list(cases)+[('model-file','none','private','success' if trace else 'seal'),('model-dir','none','store','success' if trace else 'final')]
        if trace and calibrate:cases_here.extend([('mode-calibration','none','none','success'),('calibration-collision','none','none','success')])
        for region in ('private','public'):
            for op in ('open-read','read','readback-different'):
                cases_here.append(('readback-error',op,region,'seal' if trace else 'success'))
            cases_here.append(('double-error','write',region,'seal'))
        ev=dict(scope='host-native stub: no Vita or network',compiler=cmd,diagnostics=trace,source_sha256=h((src/'wbq_io.h').read_bytes()),cases=[])
        for i,(mode,op,path,want) in enumerate(cases_here):
            d=td/f'case-{i:02}';prepare(d,sfo)
            c=[str(x),mode,op,paths[path]];q=subprocess.run(c,cwd=d,capture_output=True,text=True)
            assert q.returncode==0,(i,mode,op,path,q.returncode,q.stdout,q.stderr)
            l=q.stdout.strip();a=dict(t.split('=',1) for t in l.split())
            print(f'{path}: {l}',flush=True)
            assert int(a['handoff'])==int(want=='success'),(want,a)
            assert (int(a['rc'])<0)==(want=='seal') and (int(a['final_rc'])<0)==(want!='success'),(want,a)
            if want=='seal':assert int(a['pair'])==0
            if mode in ('model-file','model-dir'):
                assert a['total_injections']==('0' if trace else '1'),a
                assert a['create_mode']==(('0606' if trace else '0600') if mode=='model-file' else ('0707' if trace else '0700')),a
            if not trace and mode=='readback-error':assert int(a['injected'])==0,a
            elif op!='none':assert int(a['injected'])>=1,(a,path)
            if mode=='double-error':assert int(a['secondary'])>=1,(a,path)
            if trace and not observe and mode in ('os-error','double-error','readback-error'):
                assert a['phase']=={'private':'private-receipt','public':'public-receipt','store':'store'}.get(path,'stage-check'),a
                assert a['op']=={'zero-write':'write','readback-different':'readback'}.get(op,op) and a['path']==paths[path],(a,op,path)
                # A zero-byte write is a protocol error, not a negative native error.
                if op=='zero-write':assert a['raw']=='00000000' and a['has_raw']=='1',a
                elif op=='readback-different':assert a['raw']=='00000000' and a['has_raw']=='0',a
                else:assert a['raw']=='80010005' and a['has_raw']=='1',(a,op,path)
            ev['cases'].append(dict(mode=mode,injection=op,path=paths[path],expected=want,argv=c,rc=q.returncode,stdout=q.stdout,stderr=q.stderr))
        if out:out.write_bytes((json.dumps(ev,indent=2)+'\n').encode())
        print(f'HOST: {len(cases_here)}/{len(cases_here)} case outcomes, diagnostics={int(trace)}')
if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--source-dir',type=Path,default=S);a.add_argument('--out',type=Path);a.add_argument('--observe',action='store_true');a.add_argument('--calibrate',action='store_true');args=a.parse_args();run(args.source_dir,args.out,args.observe,args.calibrate)
