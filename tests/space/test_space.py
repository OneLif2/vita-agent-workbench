"""M3 transport spy: run unmodified cmd_update and assert PUT is unreachable on failures."""
import contextlib, io,sys, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
r=Path(__file__).resolve().parents[2];sys.path.insert(0,str(r/'tools'))
import wbctl as w, space_budget as s
pkg=r.parent/'v1.31/build/workbench_0131.vpk'
class Storage(unittest.TestCase):
 def report(self,line,rc=0):
  return s.probe(lambda c:(rc,line),50)
 def test_real_budget_components(self):
  facts=w.vpk_facts(pkg); b=s.requirement(facts)
  self.assertEqual(b['required'],2*facts['bytes']+2*sum(i['size'] for i in facts['members'])+2*20162+4*1024**2)
 def test_exact_fit(self):
  self.assertTrue(self.report('df volume=ux0: total=100 available=50 required=50')['ok'])
 def test_fail_closed(self):
  for a in ['','df volume=ux0: total=100 available=51 required=0','df volume=ux0: total=100 available=110 required=50','ERR no-space']:
   self.assertFalse(self.report(a)['ok'])
  self.assertEqual(self.report('ERR no-space volume=ux0: required=50 available=49 total=100',1)['state'],'insufficient')
 def test_invalid_reserve(self):
  for n in (-1,2**64):
   with self.assertRaises(ValueError):s.requirement(w.vpk_facts(pkg),n)
 def update(self,state):
  cmds=[]
  def transport(cmd,**kw):
   cmds.append(cmd)
   if cmd=='ver':return 0,'wb version=01.30 build=01.30-live-storage1 abi=3 proto=wb10 run=1111111111111111 payload=none uptime_ms=123'
   if cmd.startswith('df '):
    n=int(cmd.split()[1])
    if state=='unknown':return 255,'disconnected'
    if state=='low':return 1,f'ERR no-space volume=ux0: required={n} available=1 total={n+1}'
    return 0,f'df volume=ux0: total={2*n} available={n} required={n}'
   raise AssertionError('unexpected network mutation '+cmd)
  args=SimpleNamespace(vpk=str(pkg),yes=(state!='enough'),force=False,json=False,timeout=10,no_apply=True)
  with patch.object(w,'ssh',side_effect=transport),contextlib.redirect_stdout(io.StringIO()) as f:rc=w.cmd_update(args)
  self.assertEqual(len(cmds),2)
  return rc,f.getvalue()
 def test_no_put_on_low_or_missing(self):
  for s_ in ['low','unknown']:
   rc,out=self.update(s_);self.assertEqual(rc,8);self.assertIn('nothing uploaded',out)
 def test_sufficient_dry(self):
  rc,out=self.update('enough');self.assertEqual(rc,0);self.assertIn('DRY',out)
if __name__=='__main__':unittest.main(verbosity=2)
