"""Offline digest review; genuine native manifest and fragmented interactive PTY, no sockets."""
from __future__ import annotations
import argparse,contextlib,hashlib,io,json,socket,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
import review_digest as r
sys.path.insert(0,str(ROOT/'tests/stub'))
from self_fixture import fixture as core_fixture
import r1ctl
PIN='a'*64;SID='b'*64;OLD='c'*64;RUN='1234567890ABCDEF'
MAN='0123456789abcdef'*4;VSHA='d'*64
def expected(v='01.81'):
    return dict(title='INAP00018',version='01.82',build='01.82-live-next',receipt='WBQ2 01.82 '+MAN+' 31415',
      manifest=MAN,bytes=31415,groups=r.groups(MAN),vpk_sha256=VSHA,source_version=v,source_build=v+'-live-source',
      source_run=RUN,host_sha256=PIN,stage_transport=OLD)
class Channel:
    def __init__(self,e):
        v=e['source_version'];self.e=e;self.seen=[];self.alter=lambda cmd,k,text:text;self.rc=0
        self.buf=bytearray(f'VITA AGENT TERMINAL {v} (Workbench)\r\nType help for commands.\r\nux0:/> '.encode())
    def sendall(self,b):
        cmd=b.decode('ascii').removesuffix('\n');self.seen.append(cmd);e=self.e;v=e['source_version']
        rows={'ver':f'wb version={v} build={e["source_build"]} abi=3 proto=wb10 run={RUN} payload=none uptime_ms=14',
          'status':f'run={RUN} uptime_ms=14 ssh=connected cmds=3 payload=none core={v} last_install=none peer=127.0.0.1:2222',
          'pending':'pending-core: '+e['receipt']+'\n','r1-status':f'r1 state=none source_run=- nonce=- target=- run={RUN} manifest=-',
          'r1-review':f'OK r1-review model=local-review title=INAP00018 target=01.82 bytes=31415 source_run={RUN}\ngroups='+' '.join(e['groups']),
          'exit':'Bye.'}
        text=self.alter(cmd,self.seen.count(cmd),rows[cmd]);msg=f'{cmd}\n{text}\n'+('' if cmd=='exit' else 'ux0:/> ')
        self.buf.extend(msg.replace('\n','\r\n').encode())
    def recv(self,n):part=self.buf[:min(n,7)];del self.buf[:len(part)];return bytes(part)
    def recv_stderr_ready(self):return False
    def settimeout(self,_):pass
    def exit_status_ready(self):return self.seen[-1]=='exit' and not self.buf
    def recv_exit_status(self):return self.rc
class Cases(unittest.TestCase):
    def probe(self,v='01.81',alter=None,patch_e=None,local=PIN,host=PIN,sid=SID,rc=0):
        e=expected(v);ch=Channel(e);self.ch=ch;ch.rc=rc
        if alter:ch.alter=alter
        t=r.wb.Terminal(ch,host,sid)
        if patch_e:e=dict(e,**patch_e)
        return r.verify(e,lambda:contextlib.nullcontext(t),lambda:local)
    def test_0181_model_and_limited_commands(self):
        j=self.probe();self.assertEqual(j['groups_matched'],8);self.assertEqual(j['evidence'],'LOCAL_REVIEW_MODEL')
        self.assertEqual(self.ch.seen,['ver','status','ver','r1-status','pending','r1-review','ver','status','ver','r1-status','pending','exit'])
        self.assertEqual(j['approval'],'LOCAL_OWNER_REQUIRED');self.assertFalse(j['authorized_by_agent'] or j['applied'] or j['pixels_verified'])
    def test_0180_fallback_is_explicit(self):
        j=self.probe('01.80');self.assertEqual(j['evidence'],'PAIRED_PENDING_ONLY');self.assertNotIn('r1-review',self.ch.seen)
    def test_old_unsupported(self):
        with self.assertRaisesRegex(r.ReviewError,'requires 01.80'):self.probe('01.79')
    def test_all_8_groups_mismatch_individually(self):
        for i in range(8):
            def mod(c,k,s):
                if c!='r1-review':return s
                h,vals=s.split('groups=');a=vals.split();a[i]='DEADBEEF';return h+'groups='+' '.join(a)
            with self.subTest(i=i),self.assertRaisesRegex(r.ReviewError,'groups differ'):self.probe(alter=mod)
    def test_model_header_fields(self):
        for left,right in [('local-review','pixels'),('INAP00018','INAP00019'),('01.82','01.83'),('31415','31414'),(RUN,RUN[::-1])]:
            with self.subTest(left=left),self.assertRaises(r.ReviewError):
                self.probe(alter=lambda c,k,s:s.replace(left,right) if c=='r1-review' else s)
    def test_model_must_not_fall_back(self):
        for raw in ('ERR r1-review not-verified','ERR unknown command; type help','groups='+MAN,'','\x1bBAD'):
            with self.subTest(raw=raw),self.assertRaises(r.ReviewError):self.probe(alter=lambda c,k,s:raw if c=='r1-review' else s)
    def test_queue_unknown_changed_or_absent(self):
        for n in (1,2):
            for raw in ('pending-core: no','pending-core: WBQ1 01.82','ERR io-error','pending-core: WBQ2 01.82 '+MAN+' 1'):
                with self.subTest(n=n,raw=raw),self.assertRaises(r.ReviewError):
                    self.probe(alter=lambda c,k,s:raw if (c,k)==('pending',n) else s)
    def test_source_changed(self):
        for overwrite in ({'source_build':'01.81-live-other'},{'source_run':RUN[::-1]}):
            with self.subTest(overwrite=overwrite),self.assertRaises(r.ReviewError):self.probe(patch_e=overwrite)
    def test_revoke_or_authorize_during_review(self):
        for n in (1,2):
            with self.subTest(n=n),self.assertRaisesRegex(r.ReviewError,'approval|grant'):
                self.probe(alter=lambda c,k,s:s.replace('state=none','state=authorized') if (c,k)==('r1-status',n) else s)
    def test_pin_and_transport(self):
        for opts in ({'local':'d'*64},{'host':'f'*64},{'sid':OLD},{'sid':'bad'}):
            with self.subTest(opts=opts),self.assertRaises(r.ReviewError):self.probe(**opts)
    def test_incomplete_exit(self):
        with self.assertRaisesRegex(r.wb.Refused,'missing graceful exit'):self.probe(rc=1)
    def test_argparse_rejects_apply(self):
        parser=argparse.ArgumentParser();sub=parser.add_subparsers();r.register(sub)
        args=['review-digest','--vpk','x','--sha256',VSHA,'--stage','f','--json']
        self.assertTrue(parser.parse_args(args).json)
        for opt in ('--yes','--apply','--force'):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):parser.parse_args(args+[opt])
    def test_endpoint_fails_before_local_or_remote_actions(self):
        rc,out=r.execute(None,('127.0.0.1','22','other'),lambda *a:self.fail('loader called'),lambda *a:self.fail('ssh called'))
        self.assertEqual((rc,out['status']),(78,'TRUST_ERROR'))
    def test_duplicate_stage_keys(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'stage.json';path.write_text('{"m":1,"m":2}')
            with self.assertRaisesRegex(r.ReviewError,'ambiguous'):r.load_expected('unused',VSHA,path)
    def test_real_local_native_manifest_not_archive_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);vpk=root/'fixture.vpk';stage=root/'stage.json'
            with zipfile.ZipFile(ROOT/'build/testapp.vpk') as z:sfo=z.read('sce_sys/param.sfo').replace(b'INAP00020',b'INAP00018').replace(b'01.01\0',b'01.82\0')
            with zipfile.ZipFile(vpk,'w') as z:
                z.writestr('eboot.bin',core_fixture((b'01.82-live-next\0',)));z.writestr('sce_sys/param.sfo',sfo);z.writestr('workbench_payload.suprx',b'offline fixture')
            sha=hashlib.sha256(vpk.read_bytes()).hexdigest();pk=r1ctl.local_package(vpk,sha,'01.82-live-next')
            j=dict(result='STAGED_NOT_APPLIED',pending=pk['receipt'],idle_source_run=RUN,package=pk,
                   source=dict(channel='one interactive PTY',version='01.81',build='01.81-live-source',run=RUN,host_sha256=PIN,transport_sha256=OLD))
            stage.write_text(json.dumps(j));result=r.load_expected(vpk,sha,stage)
            self.assertNotEqual(result['vpk_sha256'],result['manifest']);self.assertEqual(''.join(result['groups']).lower(),pk['manifest'])
            with self.assertRaises(r.ReviewError):r.load_expected(vpk,'a'*64,stage)
            q=dict(j,pending='WBQ2 01.82 '+sha+' 12345');stage.write_text(json.dumps(q))
            with self.assertRaisesRegex(r.ReviewError,'reconstructed'):r.load_expected(vpk,sha,stage)

if __name__=='__main__':
    with patch.object(socket,'create_connection',side_effect=AssertionError('device/network forbidden')):
        unittest.main(verbosity=2)
