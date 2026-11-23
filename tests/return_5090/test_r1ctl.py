"""Local only: strict acceptance decisions and the actual CLI path against a fake session."""
import contextlib, hashlib, io, os, sys, tempfile, unittest, zipfile, struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
r=Path(__file__).resolve().parents[2];sys.path.insert(0,str(r/'tools'))
import r1ctl as m
A='0'*15+'1';B='0'*15+'2';N='4'*32;H='5'*64;M='6'*64;OLD='01.33';NEW='01.34'
def ver(v,run,ms):return f'wb version={v} build={v}-live-r1 abi=3 proto=wb10 run={run} payload=none uptime_ms={ms}'
def stat(v,run):return f'run={run} uptime_ms=2 ssh=connected cmds=2 payload=none core={v} last_install=none peer=192.0.2.10:2222'
pk={'version':NEW,'build':NEW+'-live-r1','manifest':M,'receipt':'WBQ2 '+NEW+' '+M+' 1234','vpk_sha256':'1'*64}
def state(s='authorized',run=A,src=A,n=N):return f'r1 state={s} source_run={src} nonce={n} target={NEW} run={run} manifest={M}'
class Fake:
 def __init__(self,v=OLD,run=A,st=None,ssid='x',new=False,manual=False):
  self.fp=H;self.pinhash='9'*64;self.sid=ssid;self.cmds=[];self.v=v;self.run=run;self.st=st or state('none' if manual else ('returned' if new else 'authorized'),run=run)
 def __enter__(self):return self
 def __exit__(self,*_):pass
 def ok(self,c):
  rc,out=self.cmd(c);assert not rc;return out
 def cmd(self,c):
  self.cmds.append(c)
  if c=='r1-status':return 0,self.st
  if c=='ver':return 0,ver(self.v,self.run,1 if self.cmds.count('ver')%2 else 3)
  if c=='status':return 0,stat(self.v,self.run)
  if c=='pending':return 0,'pending-core: '+pk['receipt']
  if c=='apply-return '+N:return 0,'OK updater installed; ssh will drop'
  raise AssertionError(c)
def args(p,phase):return SimpleNamespace(records=p,phase=phase,vpk=p/'x.vpk',sha256='1'*64,build=NEW+'-live-r1',yes=True,no_owner_input=True)
class Tests(unittest.TestCase):
 def test_00_compressed_identity_but_physical_manifest(self):
  parent=r.parent/'v1.86/build/workbench_0187.vpk'
  self.assertEqual(hashlib.sha256(parent.read_bytes()).hexdigest(),'909bae8f88d9ad57e42e91cb748abdfb3ae187b6ad1a6b9f52a843d74fb48883')
  compressed=(Path(__file__).with_name('compressed-0187.bin')).read_bytes()
  self.assertEqual(hashlib.sha256(compressed).hexdigest(),'d621366227ea8e1c730383311a9b481fccf38f0852a647a5da8f9c3fc0bb597e')
  build='01.87-live-autoentry';self.assertNotIn(build.encode()+b'\0',compressed)
  baseline=m.local_package(parent,hashlib.sha256(parent.read_bytes()).hexdigest(),build)
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'fixture.vpk'
   def write(core):
    with zipfile.ZipFile(parent) as source,zipfile.ZipFile(path,'w') as dest:
     original=source.read('eboot.bin')
     for info in source.infolist():dest.writestr(info,core if info.filename=='eboot.bin' else source.read(info))
    return original,hashlib.sha256(path.read_bytes()).hexdigest()
   original,approved=write(compressed);got=m.local_package(path,approved,build)
   self.assertEqual(int(got['receipt'].split()[-1]),int(baseline['receipt'].split()[-1])-len(original)+len(compressed))
   self.assertNotEqual(got['manifest'],baseline['manifest'])
   for core in (b'not-a-SELF '+build.encode()+b'\0',compressed+build.encode()+b'\0'):
    _,approved=write(core)
    with self.assertRaisesRegex(m.Stop,'invalid approved core SELF'):m.local_package(path,approved,build)
   bad=bytearray(compressed);struct.pack_into('<Q',bad,0x80,0x2f00000000000002);_,approved=write(bytes(bad))
   with self.assertRaisesRegex(m.Stop,'invalid approved core SELF'):m.local_package(path,approved,build)
 def test_01_manifest_exact_approved_previous_package(self):
  vpk=r.parent/'v1.32/build/workbench_0132.vpk';h=hashlib.sha256(vpk.read_bytes()).hexdigest()
  self.assertEqual(h,'7692e0b5c3dc949cecfb386e6cc53542eb5071903873f10d2627ca8b2dac702c')
  a=m.local_package(vpk,h,'01.32-live-wbq2')
  self.assertRegex(a['receipt'],r'^WBQ2 01\.32 [0-9a-f]{64} 2050788$')
  with self.assertRaises(m.Stop):m.local_package(vpk,'0'*64,'01.32-live-wbq2')
  with self.assertRaises(m.Stop):m.local_package(vpk,h,'01.32-wrong')
 def dos(self,f,a):
  with patch.object(m,'Session',return_value=f),patch.object(m,'local_package',return_value=pk),contextlib.redirect_stdout(io.StringIO()):
   return m.process(a)
 def test_02_origin_bootstrap_unsupported(self):
  f=Fake(v='01.32');snap=m.sample(f)
  with self.assertRaisesRegex(m.Stop,'source cannot grant'):m.auth(f,snap,pk)
  self.assertEqual(f.cmds,['ver','status','ver'])
 def test_03_observe_is_never_r1_success(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);f=Fake();self.assertEqual(self.dos(f,args(p,'observe')),0)
   self.assertEqual(m.get(next(p.glob('observe-*.json')))['verdict'],'OBSERVED_NOT_R1')
 def test_04_expired_revoked_different_run_or_manifest(self):
  for st in (state('expired'),state('none'),state('authorized',src=B),state().replace(M,'0'*64)):
   with tempfile.TemporaryDirectory() as t:
    p=Path(t);f=Fake(st=st);self.assertEqual(self.dos(f,args(p,'capture')),2)
    self.assertFalse((p/'physical-authorization.json').exists());self.assertFalse(any(c.startswith('apply') for c in f.cmds))
 def test_05_capture_submit_once_collect(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);self.assertEqual(self.dos(Fake(),args(p,'capture')),0)
   revoked=Fake(st=state('none'));self.assertEqual(self.dos(revoked,args(p,'submit')),2);self.assertFalse(any(c.startswith('apply') for c in revoked.cmds))
   f=Fake();self.assertEqual(self.dos(f,args(p,'submit')),0);self.assertEqual(f.cmds.count('apply-return '+N),1)
   f=Fake();self.assertEqual(self.dos(f,args(p,'submit')),2);self.assertFalse(any(c.startswith('apply') for c in f.cmds))
   for f in [Fake(v=NEW,run=A,new=True),Fake(v=NEW,run=B,manual=True),Fake(v=NEW,run=B,st=state('returned',run=B,n='8'*32))]:
    self.assertEqual(self.dos(f,args(p,'collect')),2)
   f=Fake(v=NEW,run=B,new=True);f.fp='7'*64;self.assertEqual(self.dos(f,args(p,'collect')),2)
   f=Fake(v=NEW,run=B,new=True);a=args(p,'collect');a.no_owner_input=False;self.assertEqual(self.dos(f,a),2)
   f=Fake(v=NEW,run=B,new=True);self.assertEqual(self.dos(f,args(p,'collect')),0)
   self.assertEqual(f.cmds,['ver','status','ver','r1-status'])
 def test_07_offline_preview_never_opens_ssh(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)
   with patch.object(m,'Session',side_effect=AssertionError('no connections allowed')),patch.object(m,'local_package',return_value=pk),contextlib.redirect_stdout(io.StringIO()):
    self.assertEqual(m.process(args(p,'preview')),0)
   info=m.get(next(p.glob('preview-*.json')))
   self.assertEqual((info['verdict'],info['events'],info['package']['manifest']),('PREVIEW_ONLY',[],M))
 def test_06_lost_ack_never_reissues(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);self.dos(Fake(),args(p,'capture'));f=Fake();base=f.cmd
   def cmd(c):
    if c.startswith('apply-return'):raise EOFError
    return base(c)
   f.cmd=cmd;self.assertEqual(self.dos(f,args(p,'submit')),2)
   self.assertTrue((p/'issued.json').exists())
   f=Fake();self.assertEqual(self.dos(f,args(p,'submit')),2);self.assertFalse(f.cmds)
if __name__=='__main__':unittest.main(verbosity=2)
