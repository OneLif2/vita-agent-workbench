"""Cross-check C dispatch, canonical signed bytes and the actual host command driver (mock transport)."""
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
import os, subprocess as sp, sys, tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
here=Path(__file__).resolve().parent; root=here.parents[1]; src=root/'source'
sys.path.insert(0,str(root/'tools'))
import app_patch as p
remote='ux0:/VITA-POC/test-0112.bin'; run='ABCDEF0123456789'
plan=f'app patch plan {p.TITLE} {p.VERSION} {remote}'
scalars=' '.join(['a'*64,'b'*64]); apply=plan.replace(' plan ',' apply ')+' '+scalars
with tempfile.TemporaryDirectory() as tmp:
    exe=Path(tmp)/('probe.exe' if os.name=='nt' else 'probe')
    sp.run(['gcc','-Wall','-Wextra','-Werror','-std=c11','-O2','-I',str(src),str(here/'probe.c'),
            *[str(src/(n+'.c')) for n in ('wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(exe)],check=True)
    def call(*args):
        return sp.run([str(exe),*args],capture_output=True,text=True)
    for cmd,argc in ((plan,1),(apply,3),(plan.replace(remote,'"'+remote+'"'),1)):
        got=call(cmd);assert got.returncode==0 and f'PATCH {argc} {remote}' in got.stdout,got
    rejects=[plan.replace(p.TITLE,'INAP00018'),plan.replace(p.VERSION,'01.14'),plan+' extra',
             plan.replace(remote,'/inbox/a.bin'),plan.replace(remote,remote+'/b.bin'),plan.replace('test-0112.bin','../a.bin'),
             apply[:-1],apply.upper(),apply.replace(scalars,scalars.upper()),plan.replace('plan','apply'),apply.replace('apply','plan')]
    for cmd in rejects:
        got=call(cmd);assert got.returncode==2 and 'PATCH ' not in got.stdout,got
    raw=p.message(run,remote);r=call('message',run,remote);assert r.returncode==0 and r.stdout.encode()==raw
    for badrun,badpath in [('0'*16,remote),('x'*16,remote),(run,'ux0:/app/RJGM52237/eboot.bin'),(run,remote+'/.bin')]:
        assert call('message',badrun,badpath).returncode!=0
    # Ephemeral host-only signer; no owner secret, enrollment or device action.
    key=ec.generate_private_key(ec.SECP256R1()); alg=ec.ECDSA(hashes.SHA256())
    sig=key.sign(raw,alg);key.public_key().verify(sig,raw,alg)
    for old,new in [('WB-APP-PATCH-v1','WB-APP-APPROVE-v1'),(run,'F'*16),(remote,remote+'x'),(p.RECIPE,'0'*64),(p.TITLE,'INAP00018'),(p.VERSION,'01.14'),(p.VPK,'1'*64)]:
        try:key.public_key().verify(sig,raw.replace(old.encode(),new.encode()),alg)
        except InvalidSignature:continue
        raise AssertionError(old)
snap=SimpleNamespace(size=p.BYTES,sha256=p.BOOT)
ident=dict(version='02.20',build='02.20-turbo-term',run=run,host_sha256='pin',transport_sha256='transport')
class Terminal:
    def __init__(self,reply=None,base='01.12'):self.commands=[];self.puts=[];self.reply=reply;self.base=base;self.ident=ident.copy()
    def check(self):return self.ident
    def push(self,s,path):
        self.puts.append(path);return dict(action='put',remote=path,bytes=s.size,sha256=s.sha256)
    def _app_transcript_and_exit(self,cmd,timeout):
        self.commands.append(cmd);op=cmd.split()[2]
        v=dict(stdout='OK app-patch'+('-plan' if op=='plan' else '')+f' title={p.TITLE} base={self.base} app_ver={p.VERSION} eboot_sha256={p.BOOT}\n',
               shell_exit=0,host_sha256='pin',transport_sha256='transport')
        if self.reply is not None:v.update(self.reply)
        return v
    @contextmanager
    def open(self):yield self
def check(t,op,s=snap,path=remote):
    def sign(msg):
        assert op=='apply' and msg==p.message(run,path or t.puts[-1]);return scalars
    return p.perform(op,s,path,opener=t.open,sign=sign,notice=lambda _:None)
for op in ('check','plan','apply'):
    for path in (remote,None):
        t=Terminal();ret=check(t,op,path=path)
        assert len(t.puts)==int(op!='check' and not path) and len(t.commands)==int(op!='check')
        if op!='check':assert ret['remote']==(path or t.puts[0])
for base_ver in ('01.09','01.10','01.12','01.13','01.15'):
    t=Terminal(base=base_ver);assert check(t,'apply')['base']==base_ver
def refused(t,op,exc,s=snap):
    try:check(t,op,s)
    except exc:return
    raise AssertionError('unexpected acceptance')
for version,tag in [('02.13','02.13-live-patch'),('02.14','02.14-live-batch'),('02.15','02.15-live-fastsftp'),('02.18','02.17-live-shell'),('02.18','unreviewed')]:
    t=Terminal();t.ident.update(version=version,build=tag);refused(t,'apply',ValueError);assert not t.commands and not t.puts
t=Terminal();t.ident['version']='02.11';refused(t,'apply',ValueError);assert not t.puts and not t.commands
t=Terminal();refused(t,'apply',ValueError,SimpleNamespace(size=p.BYTES,sha256='0'*64));assert not t.commands
for reply,exc in [({'stdout':'ERR app-patch signature-or-state\n'},p.w.DeviceRefused),
                  ({'stdout':'patch-note private-stage-retained no-promotion\nERR app-patch phase=copy reason=hash\nERR io-error\n'},p.w.DeviceRefused),
                  ({'stdout':'ERR app-patch phase=publish-outcome-unknown reason=native\nERR io-error\n'},p.w.Inconclusive),
                  ({'stdout':''},p.w.Inconclusive),({'transport_sha256':'wrong'},p.w.Inconclusive),
                  ({'shell_exit':1},p.w.Inconclusive)]:
    t=Terminal(reply);refused(t,'apply',exc);assert len(t.commands)==1 and not t.puts
print('PASS interactive-only C dispatch, canonical C/Python agreement, signed fields, host receipt handling, plan, apply, reuse and no retry (no device).')
