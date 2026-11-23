"""Offline integration: paired terminal staging transcript -> automatic comparison; no Vita or network."""
import contextlib,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
import stage_review as x
P='a'*64; H='b'*64; M='c'*64; RUN='123456789ABCDEF0'; EP=(x.w.HOST,str(x.w.PORT),x.w.USER)
def source(v='01.81'):return dict(version=v,build=v+'-live',run=RUN,host_sha256=P,channel='one interactive PTY',transport_sha256='d'*64)
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup); d=Path(self.tmp.name)
  self.a=NS(vpk=d/'some.vpk',sha256=H,host_pin=P,build='01.82-live',records=d/'evidence',prior_return=None,stage=True)
  self.p=dict(version='01.82',build=self.a.build,vpk_sha256=H,manifest=M,receipt='WBQ2 01.82 '+M+' 123456',members=['member mock'],size=555,expanded=321,required=500)
  self.events=[];self.s=source()
 def flow(self,ret=None,stage_error=False):
  def pin(p):self.assertEqual(p,P);self.events.append('pin')
  def pkg(a):self.assertIs(a,self.a);self.events.append('pkg');return self.p
  def stage(a,p,d,log):
   self.events.append('stage-once')
   if stage_error:raise ValueError('disconnect')
   r=dict(result='STAGED_NOT_APPLIED',source=self.s)
   x.store(d/'stage-confirmed.json',r);return r
  def review(a,d):
   self.assertTrue((d/'stage-confirmed.json').is_file());self.events.append('review-readonly')
   expected=dict(groups=['CCCCCCCC']*8,manifest_sha256=M,title='INAP00018',target='01.82',vpk_sha256=H,wbq2_bytes=123456,host_sha256=P,source_run=RUN,source_version=self.s['version'],applied=False,authorized_by_agent=False)
   code,j=ret if ret is not None else (0,dict(status='MATCH',groups_matched=8,evidence='LOCAL_REVIEW_MODEL',approval='LOCAL_OWNER_REQUIRED'))
   return code,{**expected,**j}
  return x.workflow(self.a,EP,get_package=pkg,check_pin=pin,do_stage=stage,review=review)
 def test_chain_after_commit(self):
  rc,r=self.flow();self.assertEqual((rc,r['status'],r['applied']),(0,'QUEUED_AND_REVIEWED',False))
  self.assertEqual(self.events,['pin','pkg','stage-once','review-readonly']);self.assertEqual(json.loads((self.a.records/'digest-review.json').read_bytes())['groups_matched'],8)
 def test_dry_never_connects(self):
  self.a.stage=False;self.assertEqual(self.flow()[1]['status'],'LOCAL_PREVIEW_ONLY');self.assertEqual(self.events,['pin','pkg']);self.assertFalse(self.a.records.exists())
 def test_wrong_endpoint_no_io(self):
  with self.assertRaises(ValueError):x.workflow(self.a,('other','2222','pi'),check_pin=lambda _:self.fail())
 def test_no_restage_in_existing_directory(self):
  self.flow();self.events=[];self.assertRaises(FileExistsError,self.flow);self.assertEqual(self.events,['pin','pkg'])
 def test_inconclusive_submission_is_not_reissued_or_reviewed(self):
  self.assertNotEqual(self.flow(stage_error=True)[0],0);self.assertEqual(self.events.count('stage-once'),1);self.assertNotIn('review-readonly',self.events)
 def test_mismatch_stays_queued(self):
  rc,r=self.flow((3,dict(status='MISMATCH',groups_matched=7)));self.assertNotEqual(rc,0);self.assertTrue(r['queued'] and r['do_not_restage'])
 def test_incomplete_even_if_tool_exit_zero(self):
  self.assertNotEqual(self.flow((0,dict(status='MATCH',groups_matched=7,approval='LOCAL_OWNER_REQUIRED',evidence='LOCAL_REVIEW_MODEL')))[0],0)
 def test_stale_equally_sized_digest_result(self):
  self.assertNotEqual(self.flow((0,dict(status='MATCH',groups_matched=8,groups=['DDDDDDDD']*8,approval='LOCAL_OWNER_REQUIRED',evidence='LOCAL_REVIEW_MODEL')))[0],0)
 def test_no_implied_owner_consent(self):
  self.assertNotEqual(self.flow((0,dict(status='MATCH',groups_matched=8,approval='AUTHORIZED',evidence='LOCAL_REVIEW_MODEL')))[0],0)
 def test_0180_cannot_claim_display_model(self):
  self.s=source('01.80');self.assertNotEqual(self.flow()[0],0)
 def test_0180_fallback_explicit(self):
  self.s=source('01.80');rc,r=self.flow((0,dict(status='MATCH',groups_matched=8,approval='LOCAL_OWNER_REQUIRED',evidence='PAIRED_PENDING_ONLY')));self.assertEqual((rc,r['evidence']),(0,'PAIRED_PENDING_ONLY'))
 def test_invalid_live_power(self):
  ok=['payload online=1','payload battery=95','payload temp_c=30'];self.assertTrue(x.enough_power(ok))
  for bad in (ok[1:],ok+ok,['payload online=0',*ok[1:]],['payload online=1','payload battery=24',ok[2]]):self.assertFalse(x.enough_power(bad))
 def test_authorized_not_idle(self):
  self.assertFalse(x.grant_idle([f'r1 state=authorized source_run={RUN} nonce='+'E'*32+f' target=01.82 run={RUN} manifest={M}'],self.s,None))
 def test_real_stage_dispatch_is_pty_only_and_stops_at_queue(self):
  s=self.s;p=self.p;a=self.a;d=a.records;d.mkdir();log=[];none=f'r1 state=none source_run=- nonce=- target=- run={RUN} manifest=-'
  class T:
   ch=mock.Mock()
   def check(self):return dict(s)
   def push(self,src,rem):return dict(action='put',remote=rem,bytes=p['size'],sha256=H)
  seen=[];committed=False
  def wire(t,c):
   nonlocal committed
   seen.append(c)
   if c=='pending':return ['pending-core: '+(p['receipt'] if committed else 'no')]
   if c=='r1-status':return [none]
   if c=='updater check':return ['OK updater-check title=INAP00019 helper=reuse epoch=01.73 promote=0']
   if c=='ext sys':return ['payload online=1','payload battery=34','payload temp_c=30']
   if c=='df 500':return ['df volume=ux0: total=900 available=700 required=500']
   if c.startswith('tree-stat '):return ['TTY1 OK ABSENT']
   if c.startswith('inspect '):return ['file bytes=555 sha256='+H,*p['members'],'title_id=INAP00018 app_ver=01.82 title=Vita Agent Workbench']
   if c.startswith('plan '):return ['plan file bytes=555 sha256='+H,'plan title=INAP00018 app_ver=01.82 running=01.81 installed=01.81 title_ok=1','plan verdict=newer core=replace payload=replace queue=yes force=no','plan member mock']
   if c.startswith('install '):
    self.assertTrue((d/'stage-issued.json').is_file());self.assertTrue(c.endswith(' --no-reload'));self.assertFalse(committed);committed=True
    return ['OK install version=01.82 title=INAP00018 files=3 bytes=321 payload=none core=queued session=kept']
   self.fail('Unexpected command: '+c)
  with mock.patch.object(x.w,'paired_terminal',lambda:contextlib.nullcontext(T())),mock.patch.object(x,'reply',wire),mock.patch.object(x,'trust',lambda _:None):
   r=x.stage(a,p,d,log)
  self.assertTrue(committed);self.assertEqual(r['result'],'STAGED_NOT_APPLIED');self.assertEqual(r['source'],s);self.assertFalse(any('apply' in c for c in seen))
if __name__=='__main__':unittest.main(verbosity=2)
