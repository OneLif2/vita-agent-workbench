"""Host-fixture coverage of R1 notice after pinned WBQ2 review; no Vita/network or apply."""
from __future__ import annotations
import argparse
import contextlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/digest_review_cli'))
from run import Channel,RUN,PIN,SID,OLD,MAN,VSHA,expected,r
import stage_review as s

CMD='r1-notice '+MAN
def fixture(v='01.82'):
    e=expected(v)
    e.update(version='01.83',build='01.83-live-next',receipt='WBQ2 01.83 '+MAN+' 31415')
    return e
def ack(e):
    return f"OK r1-notice title={e['title']} target={e['version']} bytes={e['bytes']} source_run={RUN} manifest={MAN}"
class NotifyChannel(Channel):
    def __init__(self,e,alter):
        super().__init__(e);self.wire=alter
        self.alter=lambda c,k,v:alter(c,k,v.replace('target=01.82','target='+e['version']))
    def sendall(self,data):
        text=data.decode().removesuffix('\n')
        if text==CMD:
            self.seen.append(text)
            a=self.wire(text,self.seen.count(text),ack(self.e))
            self.buf.extend((text+'\n'+a+'\nux0:/> ').replace('\n','\r\n').encode())
        else:super().sendall(data)

class Cases(unittest.TestCase):
    def prepare(self,v='01.82',alter=lambda c,k,x:x,**override):
        self.e=fixture(v);self.e.update(override)
        self.c=NotifyChannel(self.e,alter);self.t=r.wb.Terminal(self.c,PIN,SID)
        return self.e,self.t
    def issued(self,state):
        self.assertNotIn(CMD,self.c.seen)
        self.assertEqual(state['transport_sha256'],SID)
        self.mark=state
    def review(self,v='01.82',alter=lambda c,k,x:x,issue=True,trust=lambda:PIN,rc=0):
        self.prepare(v,alter);self.c.rc=rc
        return r.verify(self.e,lambda:contextlib.nullcontext(self.t),trust,
                        notice_issue=self.issued if issue else None)
    def test_01_82_notice_same_session_order_graceful_exit(self):
        j=self.review();self.assertEqual(j['notice']['status'],'ACKNOWLEDGED')
        self.assertEqual(j['notice']['manifest'],MAN)
        self.assertEqual(self.c.seen,['ver','status','ver','r1-status','pending','r1-review',
                                     'ver','status','ver','r1-status','pending',CMD,'exit'])
        self.assertEqual(self.mark['target'],'01.83')
        self.assertFalse(j['authorized_by_agent'] or j['applied'] or j['pixels_verified'])
    def test_legacy_never_writes_notice(self):
        for v in ('01.80','01.81'):
            with self.subTest(v=v):
                j=self.review(v);self.assertEqual(j['notice'],{'status':'LEGACY_SOURCE'})
                self.assertNotIn(CMD,self.c.seen)
    def test_standalone_is_read_only_even_on_new_core(self):
        j=self.review(issue=False)
        self.assertEqual(j['notice'],{'status':'NOT_REQUESTED'})
        self.assertEqual(self.c.seen[-2:],['pending','exit'])
    def test_every_ack_field_bound(self):
        for a,b in [('INAP00018','INAP00019'),('01.83','01.84'),('31415','31416'),(RUN,RUN[::-1]),(MAN,MAN[::-1])]:
            with self.subTest(a=a):
                j=self.review(alter=lambda c,k,v:v.replace(a,b) if c==CMD else v)
                self.assertEqual(j['notice']['status'],'UNCONFIRMED')
                self.assertEqual(self.c.seen.count(CMD),1)
    def test_stale_or_replaced_queue_writes_nothing(self):
        for row in ('pending-core: no','pending-core: WBQ2 01.84 '+MAN+' 31415'):
            with self.subTest(row=row),self.assertRaises(r.ReviewError):
                self.review(alter=lambda c,k,v:row if (c,k)==('pending',2) else v)
            self.assertNotIn(CMD,self.c.seen)
    def test_wrong_model_writes_nothing(self):
        with self.assertRaises(r.ReviewError): self.review(alter=lambda c,k,v:v+'x' if c=='r1-review' else v)
        self.assertNotIn(CMD,self.c.seen)
    def test_auth_changed_writes_nothing(self):
        with self.assertRaises(r.ReviewError):
            self.review(alter=lambda c,k,v:v.replace('state=none','state=authorized') if (c,k)==('r1-status',2) else v)
        self.assertNotIn(CMD,self.c.seen)
    def test_pin_changed_writes_nothing(self):
        trust=iter((PIN,'e'*64))
        with self.assertRaises(r.ReviewError):self.review(trust=lambda:next(trust))
        self.assertNotIn(CMD,self.c.seen)
    def test_refused_or_missing_ack_never_retries(self):
        for text,want in [('ERR r1-notice mismatch','REFUSED'),('ERR unknown command; type help','UNCONFIRMED'),
                          ('','UNCONFIRMED'),('ACK\nEXTRA','UNCONFIRMED')]:
            with self.subTest(text=text):
                j=self.review(alter=lambda c,k,v:text if c==CMD else v)
                self.assertEqual(j['notice']['status'],want);self.assertEqual(self.c.seen.count(CMD),1)
    def test_bad_exit_does_not_claim_display(self):
        j=self.review(rc=8);self.assertEqual(j['notice']['status'],'UNCONFIRMED')
        self.assertEqual(self.c.seen.count(CMD),1)
    def test_duplicate_disk_intent_never_writes(self):
        self.prepare()
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder);a=argparse.Namespace(vpk=d/'f.vpk',sha256=VSHA)
            s.store(d/'notice-issued.json',{'previous':'record'})
            real_verify=r.verify
            with patch.object(r,'verify',side_effect=lambda e,**opts:real_verify(e,lambda:contextlib.nullcontext(self.t),lambda:PIN,**opts)),patch.object(r,'load_expected',return_value=self.e):
                rc,result=s.automatic_review(a,d)
            self.assertNotEqual(rc,0);self.assertNotIn(CMD,self.c.seen)
            self.assertEqual(json.loads((d/'notice-issued.json').read_bytes()),{'previous':'record'})
    def workflow(self,alter=lambda c,k,x:x,v='01.82'):
        self.prepare(v,alter)
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder);a=argparse.Namespace(vpk=d/'f.vpk',sha256=VSHA,host_pin=PIN,stage=True,records=d/'new')
            p=dict(manifest=MAN,version=self.e['version'],receipt=self.e['receipt'])
            e=self.e
            original_verify=r.verify
            with patch.object(r,'verify',side_effect=lambda e,**opts:original_verify(e,lambda:contextlib.nullcontext(self.t),lambda:PIN,**opts)),patch.object(r,'load_expected',return_value=e):
                rc,j=s.workflow(a,(s.w.HOST,str(s.w.PORT),s.w.USER),check_pin=lambda _:None,get_package=lambda _:p,
                    do_stage=lambda *args:dict(result='STAGED_NOT_APPLIED',source=dict(version=v,run=RUN)))
            marker=a.records/'notice-issued.json'
            detail=json.loads((a.records/'digest-review.json').read_bytes())
            if v>='01.82':
                self.assertTrue(marker.is_file());this=json.loads(marker.read_bytes())
                self.assertEqual(this['manifest'],MAN);self.assertEqual(this['transport_sha256'],SID)
                self.assertEqual(this['source_run'],RUN)
            else:self.assertFalse(marker.exists())
            return rc,j,detail
    def test_pipeline_owner_action_and_not_installed(self):
        rc,j,_=self.workflow()
        self.assertEqual((rc,j['status'],j['target'],j['owner_action']),
                         (0,'QUEUED_AND_REVIEWED','01.83','CROSS_WHEN_APPROVAL_PROMPT_VISIBLE'))
        self.assertFalse(j['authorized_by_agent'] or j['applied'] or j['notice_screen_verified'])
    def test_pipeline_01_81_fallback(self):
        rc,j,_=self.workflow(v='01.81')
        self.assertEqual((rc,j['owner_action'],j['notice_status']),(0,'TRIANGLE_THEN_CROSS','LEGACY_SOURCE'))
    def test_pipeline_unconfirmed_ends_with_wait_no_restage(self):
        rc,j,_=self.workflow(alter=lambda c,k,v:'WRONG' if c==CMD else v)
        self.assertEqual((rc,j['status'],j['owner_action']),
                         (3,'QUEUED_AND_REVIEWED_NOTICE_UNCONFIRMED','WAIT_FOR_CONFIRMATION'))
        self.assertTrue(j['do_not_resend_notice'] and j['do_not_restage'])
    def test_path_traversal_rejected_before_stage_intent_or_device(self):
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder)
            a=argparse.Namespace(vpk=d/'..'/'f.vpk',sha256=VSHA,host_pin=PIN,stage=True,records=d/'new')
            with self.assertRaisesRegex(s.w.wb_tree.TreeError,'parent traversal'):
                s.workflow(a,(s.w.HOST,str(s.w.PORT),s.w.USER),check_pin=lambda _:None,do_stage=lambda _:self.fail('staged'))
            self.assertFalse(a.records.exists())

if __name__=='__main__':
    with patch.object(socket,'create_connection',side_effect=AssertionError('device/network forbidden')):
        unittest.main(verbosity=2)
