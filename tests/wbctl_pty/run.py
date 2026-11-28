"""Existing high-level workflows over the PTY-only adapter. Simulated storage/console; no sockets."""
import argparse,contextlib,hashlib,io,json,re,shlex,sys,tempfile,time
from pathlib import Path
from unittest import mock
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'tools'))
import wbctl as w, wbctl_pty as compat, wbterm as term
sys.path.insert(0,str(R/'tests'))
from native_identity import VERSION as FIXTURE_VERSION, BUILD as FIXTURE_BUILD

def sha(b):return hashlib.sha256(b).hexdigest()
class Device:
    def __init__(self):
        self.files={};self.cmds=[];self.dialogue=[];self.version='01.63';self.run='1'*16;self.target='';self.launch={};self.corrupt=None
    def push(self,p,path):
        if isinstance(p,term.wb_tree.FileSource):p=p.path
        self.cmds.append('put');data=p.read_bytes();assert path not in self.files
        self.files[path]=data;return dict(action='put',remote=path,bytes=len(data),sha256=sha(data))
    def pull(self,path,p,max_bytes):
        self.cmds.append('get')
        data=self.files[path];assert len(data)<=max_bytes;p.write_bytes(data)
        return dict(action='get',remote=path,bytes=len(data),sha256=sha(data))
    @contextlib.contextmanager
    def paired(self):
        self.deadline=time.monotonic()+1800;yield self
    def _transcript_and_exit(self,wire,timeout=20):
        self.dialogue.append(wire);p=shlex.split(wire);op=p[0];self.cmds.append(op)
        if op=='ver':
            # Health checks still name the installed core. The candidate header can be newer.
            if self.version==FIXTURE_VERSION:build=FIXTURE_BUILD
            elif self.version==w.CORE_VERSION:build=w.CORE_BUILD
            else:build=self.version+'-live-layout'
            out='ERR invalid or disallowed Workbench command/options' if len(p)>1 else f'wb version={self.version} build={build} abi=3 proto=wb10 run={self.run} payload=none uptime_ms=15'
        elif op=='status':out=f'run={self.run} uptime_ms=15 ssh=connected cmds=7 payload=none core={self.version} last_install=none peer=192.0.2.10:2222'
        elif op=='help':out='Workbench commands include ver status df timeline pending inspect plan shot photo-export'
        elif op=='ext':
            assert p[1]=='stat'
            out=f'F {p[2]} {len(self.files[p[2]])}' if p[2] in self.files else 'ERR not-found'
        elif op=='photo-export':out=f'OK photo-export bytes={len(self.files[p[1]])} sha256={sha(self.files[p[1]])}'
        elif op=='df':out=f'df volume=ux0: total=999999999 available=888888888 required={p[1]}'
        elif op=='inspect':out=f'file bytes={len(self.files[p[1]])} sha256={sha(self.files[p[1]])}'
        elif op=='install':
            assert p[2]=='sha256='+sha(self.files[p[1]]);self.target='01.64'
            out=f'OK install version=01.64 title=INAP00018 files=3 bytes=123 payload=none core=queued session=kept'
        elif op=='pending':out=f'pending-core: WBQ2 {self.target} '+('a'*64)+' 123'
        elif op=='apply-core':self.version=self.target;self.run='2'*16;out='OK updater installed (detail=0), launching INAP00019; ssh will drop'
        elif op=='app-install':
            assert p[1] in self.files;out='OK app-install title=INAP00020 app_ver=01.01 files=3 detail=0 session=kept'
        elif op=='launch':
            assert p[1:3]==['INAP00020','fs-smoke'];self.run='3'*16
            self.files['ux0:/data/INAP00018/testapp/result.txt']=(f'job={p[3]}\ntitle=INAP00020\ncase=fs-smoke\nbuild=01.01-testapp\nassert=write=64 read=64 match=1\nresult=PASS\n').encode()
            out=f'OK launch title=INAP00020 case=fs-smoke job={p[3]}'
        elif op=='timeline':out='stage=boot ver=01.76 run='+self.run
        else:raise AssertionError('unexpected wire op '+wire)
        if self.corrupt==op:out='ERR injected-fixture-failure'
        return {'stdout':out+'\n','shell_exit':0}

def invoke(*args):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):code=w.main(list(map(str,args)))
    return code,buf.getvalue()

def main():
    dev=Device();app=R/'build/testapp.vpk';vpk=R.parent/'v1.64/build/workbench_0164.vpk'
    with tempfile.TemporaryDirectory() as tmp,mock.patch.object(term,'paired_terminal',dev.paired),mock.patch.object(w,'JOBS_DIR',Path(tmp)/'jobs'):
        d=Path(tmp);pic=d/'fixture.jpg';pic.write_bytes(b'\xff\xd8\xffa\xff\xd9')
        assert invoke('app','plan',app)[0]==0 and not dev.cmds
        assert invoke('app','install',app)[0]==0 and not dev.cmds
        assert invoke('app','install',app,'--yes')[0]==0 and dev.cmds==['put','app-install']
        assert invoke('put',pic,'--image')[0]==0 and dev.cmds[-4:]==['help','ext','put','photo-export']
        assert invoke('put',pic,'--image')[0]==0 and dev.cmds[-3:]==['help','ext','photo-export']
        assert invoke('update',vpk,'--yes','--no-apply')[0]==0 and 'apply-core' not in dev.cmds and dev.cmds[-3:]==['put','inspect','install']
        assert invoke('apply','--version','01.64')[0]==0 and dev.version=='01.64' and dev.cmds.count('apply-core')==1
        dev.version=w.CORE_VERSION
        rc,out=invoke('test','run','fs-smoke','--vpk',app,'--timeout','2')
        assert rc==0 and 'PASS' in out and dev.cmds.count('launch')==1,(rc,out,dev.cmds)
        mark=len(dev.cmds);assert invoke('report')[0]==0 and len(dev.cmds)==mark
        assert invoke('--json','deny-check')[0]==0
        dev.corrupt='inspect';dev.version='01.63';dev.files={};mark=dev.cmds.count('install')
        assert invoke('update',vpk,'--yes','--no-apply')[0]!=0 and dev.cmds.count('install')==mark
        dev.corrupt=None;mark=len(dev.cmds)
        for c in ('exec uname','ver\napply-core','rm foo','launch INAP00018 fs-smoke 0','install ux0:/VITA-POC/x --force','get ux0:data/INAP00018/mac-public-pin.txt'):
            assert compat.exchange(c,3,None)[0]!=0
        assert compat.exchange('put ux0:/VITA-POC/x 2 sha256='+('0'*64),3,b'AB')[0]!=0 and len(dev.cmds)==mark
        def vr(ver,rid):
            return 0,f'wb version={ver} build={ver}-live-layout abi=3 proto=wb10 run={rid} payload=none uptime_ms=50'
        old='1'*16;new='2'*16
        for ending,verdict in (('01.76','verified'),('01.77','inconclusive')):
            with mock.patch.object(w,'ssh',side_effect=[vr('01.64',old),vr(ending,new)]) as probe,mock.patch.object(w.time,'sleep'):
                assert w.wait_for_version('01.76',old,2)[0]==verdict
                assert [call.args for call in probe.call_args_list]==[('ver',),('ver',)]
        assert not w.apply_observable(1,'ERR refused') and not w.apply_observable(0,'OK but wrong')
        assert w.apply_observable(255,'UNKNOWN terminal disconnected') and w.apply_observable(0,'OK updater installed (detail=0), launching INAP00019; ssh will drop')
        reused='OK updater reused (detail=1), launching INAP00019; ssh will drop'
        assert w.apply_observable(0,reused) and not w.apply_observable(0,reused.replace('detail=1','detail=0'))
        assert not w.apply_observable(0,reused.replace('reused','installed'))
        assert not w.apply_observable(0,'preamble '+reused) and not w.apply_observable(255,'WARN\nERR refused')
    print('PASS wbctl terminal-only adapter: app plan/install (including no-authorization dry run), photo stage/import/reuse, WBQ2 update dry-apply gate, explicit apply + fresh run, TestApp job matching + local report')
    print('PASS no install after failed device digest; malformed commands/paths/unsafe flags and differing upload bytes refused before terminal dispatch; parser denial is not an exec exit status')
    print('HOST simulation only: high-level workflow and adapter tested; no actual upgrade, job, Photos or Vita access')
if __name__=='__main__':main()
