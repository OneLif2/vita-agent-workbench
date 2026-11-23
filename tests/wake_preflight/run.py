"""Offline evidence for fixed, read-only wake preflight. Never accesses a Vita."""
from __future__ import annotations
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import wake_preflight as w

H='1'*64; HFILE='2'*64; HOST2='3'*64; OWNER='4'*64
SID1='5'*64; SID2='6'*64; SID3='7'*64
RUN='1234567890ABCDEF'; RECVRUN='8765432109ABCDEF'; NONCE='f'*32
VER='01.82'; BUILD='01.82-live-r1notice'
IDLE=f'r1 state=none source_run=- nonce=- target=- run={RUN} manifest=-'
RETURNED=f'r1 state=returned source_run={RECVRUN} nonce={"A"*32} target={VER} run={RUN} manifest={"b"*64}'
PROFILE=dict(schema='wb.wake.local-enrollment.v1',wb_sha256=H,receiver_sha256=HOST2,owner_sha256=OWNER)
ENDPOINT=(w.wb.HOST,str(w.wb.PORT),w.wb.USER)
def proof(c=NONCE,**patch):
    return dict(dict(receiver_run=RECVRUN,challenge=c,target='INAP00018',receiver_sha256=HOST2,owner_sha256=OWNER,
        transport_sha256=SID2,subsystem=w.SUBSYSTEM),**patch)


class Tty:
    def __init__(self,log,sid,state,run=RUN,pending='pending-core: no'):
        self.log=log;self.transport_id=sid;self.version=VER;self.host_pin=H
        self.state=state;self.run=run;self.pending=pending
    def check(self):
        self.log+=['ver','status','ver']
        return dict(version=self.version,build=BUILD,run=self.run,host_sha256=self.host_pin,transport_sha256=self.transport_id,
                    channel='one interactive PTY')
    def one(self,cmd):
        self.log.append(cmd)
        if cmd=='r1-status':return self.state
        raise AssertionError('unexpected interactive WB verb')
    def rows(self,cmd):
        self.log.append(cmd)
        if cmd=='pending':return [self.pending]
        raise AssertionError('unexpected interactive WB verb')


class Workflow(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/w.PROFILE_NAME
        self.path.write_text(json.dumps(PROFILE),encoding='utf-8')
        self.log=[]
        self.before=Tty(self.log,SID1,RETURNED)
        self.after=Tty(self.log,SID3,IDLE)
        self.pair_count=0
    @contextlib.contextmanager
    def paired(self):
        self.log.append('wb-start');self.pair_count+=1
        try:yield (self.before,self.after)[self.pair_count-1]
        finally:self.log.append('wb-end')
    def receiver(self,enroll,c):
        self.log.append('ready');self.assertEqual(enroll,PROFILE);self.assertEqual(c,NONCE)
        return proof(c)
    def execute(self,**options):
        self.report={}
        defaults=dict(paired=self.paired,trust=lambda:(H,HFILE),receiver=self.receiver,nonce=lambda n:NONCE,rows=lambda t,c:t.rows(c))
        return w.preflight(self.report,self.path,**dict(defaults,**options))
    def test_preclose_ready_order_and_two_distinct_wb_sessions(self):
        self.assertEqual(self.execute(),'PREFLIGHT_READY_OWNER_CLOSE_ONLY')
        self.assertEqual(self.report['before']['run'],self.report['after']['run'])
        self.assertEqual(self.report['receiver']['target'],'INAP00018')
        self.assertEqual(self.log,['wb-start','ver','status','ver','pending','r1-status','ver','status','ver','wb-end','ready',
                                  'wb-start','ver','status','ver','pending','r1-status','ver','status','ver','wb-end'])
    def test_missing_enrollment_no_ssh_to_either_host(self):
        self.path.unlink()
        self.assertEqual(self.execute(trust=lambda:self.fail('called trust')),'NO_RECEIVER_ENROLLMENT')
        self.assertEqual(self.log,[])
    def test_profile_swapped_invalid_or_has_duplicates_before_sockets(self):
        for text in ('null','[]','{"wb_sha256":"1","wb_sha256":"2"}', json.dumps(dict(PROFILE,wb_sha256='8'*64)), '*'*2049):
            self.path.write_text(text,encoding='utf8')
            with self.subTest(text=text[:30]),self.assertRaises(ValueError):self.execute()
            self.assertEqual(self.log,[])
    def test_old_exec_profile_is_not_an_enrollment(self):
        self.path.unlink()
        self.path.with_name('wb-wake.local.json').write_text(json.dumps(PROFILE),encoding='utf8')
        self.assertEqual(self.execute(),'NO_RECEIVER_ENROLLMENT')
        self.assertEqual(self.log,[])
    def test_pending_or_active_authorization_blocks_receiver(self):
        self.before.pending='pending-core: WBQ2 01.83 abc 1'
        with self.assertRaisesRegex(w.Gate,'queue'):self.execute()
        self.assertNotIn('ready',self.log)
        self.pair_count=0
        self.before.pending='pending-core: no'
        self.before.state=RETURNED.replace('state=returned','state=authorized')
        with self.assertRaisesRegex(w.Gate,'authorization'):self.execute()
        self.assertNotIn('ready',self.log)
    def test_empty_before_is_not_enough_if_queue_changed_during_proof(self):
        self.after.pending='pending-core: WBQ2 01.83 abc 1'
        with self.assertRaisesRegex(w.Gate,'queue'):self.execute()
        self.assertIn('ready',self.log)
    def test_run_change_or_transport_reuse_not_a_preflight(self):
        self.after.run=RECVRUN
        self.after.state=IDLE.replace(RUN,RECVRUN)
        with self.assertRaisesRegex(w.Gate,'WB run'):self.execute()
        self.pair_count=0;self.after.run=RUN;self.after.state=IDLE;self.after.transport_id=SID2
        with self.assertRaisesRegex(w.Gate,'WB run'):self.execute()
    def test_receiver_profile_changed_after_signed_transport(self):
        def changed(o,n):
            self.path.write_text(json.dumps(dict(PROFILE,receiver_sha256='9'*64)),encoding='utf8')
            return self.receiver(o,n)
        with self.assertRaisesRegex(w.Gate,'enrollment changed'): self.execute(receiver=changed)
    def test_proof_unbound_target_pin_or_challenge_stops_before_second_wb(self):
        for fields in ({'target':'INAP00019'},{'challenge':'0'*32},{'receiver_sha256':'9'*64},
                       {'owner_sha256':'0'*64},{'receiver_run':'0'*16},{'subsystem':'other'},{'transport_sha256':SID1}):
            with self.subTest(fields=fields),self.assertRaisesRegex(w.Gate,'proof'):
                self.pair_count=0
                self.execute(receiver=lambda _,n:proof(**fields))
            self.assertEqual(self.pair_count,1)
    def test_receiver_timeout_is_not_retried(self):
        calls=[]
        def unavailable(o,n):
            calls.append(n);raise TimeoutError('timed out')
        with self.assertRaises(TimeoutError):self.execute(receiver=unavailable)
        self.assertEqual((calls,self.pair_count),([NONCE],1))
    def test_open_default_is_current_wb_advisory_not_old_driver(self):
        rc,j=w.open_status(ENDPOINT,self.path,paired=self.paired,trust=lambda:(H,HFILE))
        self.assertEqual((rc,j['status'],j['launch_sent']),(0,'ALREADY_RUNNING',False))
        self.assertNotIn('ready',self.log)
    def test_open_refused_never_calls_receiver_even_if_enrolled(self):
        def unavailable():
            raise ConnectionRefusedError
        opts=dict(paired=unavailable,trust=lambda:(H,HFILE))
        rc,j=w.open_status(ENDPOINT,self.path,**opts);self.assertEqual((rc,j['status'],j['launch_sent']),(3,'WAKE_UNAVAILABLE',False))
        self.path.unlink()
        rc,j=w.open_status(ENDPOINT,self.path,**opts);self.assertEqual((rc,j['status'],j['launch_sent']),(3,'NO_ENROLLED_RECEIVER',False))
    def test_saved_wb_pin_swap_between_observations(self):
        feed=iter([(H,HFILE)]*3+[(H,'f'*64)])
        with self.assertRaisesRegex(w.Gate,'WB pin changed'):self.execute(trust=lambda:next(feed))


class Key:
    def __init__(self,key=b'expected',kind=w.P256):self.key=key;self.kind=kind
    def get_name(self):return self.kind
    def asbytes(self):return self.key


class Wire:
    def __init__(self):
        self.log=[]
        self.remote=Key()
        self.owner=Key(b'owner')
        self.auth=True
        self.status=0
        self.err=False
        self.expected=f'READY {NONCE} {RECVRUN} INAP00018\n'.encode('ascii')
        self.out=[self.expected[:12],self.expected[12:],b'']
        self.profile=dict(PROFILE,receiver_sha256=w.fingerprint(self.remote),owner_sha256=w.fingerprint(self.owner))
    def paramiko(self):
        wire=self
        class C:
            def __enter__(self):return self
            def __exit__(self,*args):wire.log.append('channel-closed')
            def settimeout(self,t):wire.log.append(('channel-timeout',t))
            def invoke_subsystem(self,x):wire.log.append(('subsystem',x))
            def sendall(self,msg):wire.log.append(('request',bytes(msg)))
            def shutdown_write(self):wire.log.append('shutdown-write')
            def recv_stderr_ready(self):return wire.err
            def recv(self,n):return wire.out.pop(0)
            def exit_status_ready(self):return True
            def recv_exit_status(self):return wire.status
        class T:
            session_id=b'fresh independent sid'
            def __init__(self,sock):wire.log.append('transport')
            def __enter__(self):return self
            def __exit__(self,*args):wire.log.append('closed')
            def get_security_options(self):return SimpleNamespace(key_types=())
            def start_client(self,timeout):wire.log.append('started')
            def get_remote_server_key(self):wire.log.append('get-server-key');return wire.remote
            def auth_publickey(self,user,key):wire.log.append(('auth',user))
            def is_authenticated(self):return wire.auth
            def is_active(self):return True
            def open_session(self,timeout):wire.log.append('new-session');return C()
        return SimpleNamespace(Transport=T)
    def run(self):
        def open_socket(ep,timeout):
            self.log.append(('fixed-connect',ep));return contextlib.nullcontext(SimpleNamespace())
        def owner(_):
            self.log.append('owner-file-loaded');return self.owner
        return w.receiver_ready(self.profile,NONCE,owner_loader=owner,open_socket=open_socket,paramiko_module=self.paramiko())


class Subsystem(unittest.TestCase):
    def test_exact_single_subsystem_buffered_challenge_and_clean_exit(self):
        f=Wire();p=f.run()
        self.assertEqual(p['receiver_run'],RECVRUN)
        self.assertEqual(p['transport_sha256'],hashlib.sha256(b'fresh independent sid').hexdigest())
        self.assertEqual(f.log,[('fixed-connect',(w.wb.HOST,2224)),'transport','started','get-server-key','owner-file-loaded',
            ('auth',w.wb.USER),'new-session',('channel-timeout',4),('subsystem','wb-wake-v1'),
            ('request',f'READY {NONCE}\n'.encode()),'shutdown-write','channel-closed','closed'])
    def test_wrong_receiver_pin_and_algorithm_precede_owner_load(self):
        for k in (Key(b'wrong data'),Key(kind='ssh-rsa')):
            with self.subTest(key=k.key):
                f=Wire();f.remote=k
                with self.assertRaisesRegex(w.Gate,'receiver pin mismatch'):f.run()
                self.assertNotIn('owner-file-loaded',f.log)
    def test_wrong_owner_or_refused_auth_never_invokes_subsystem(self):
        for change in ({'owner':Key(b'unpaired')},{'auth':False}):
            with self.subTest(change=change):
                f=Wire();f.__dict__.update(change)
                with self.assertRaisesRegex(w.Gate,'owner'):f.run()
                self.assertNotIn('new-session',f.log)
    def test_strict_bounds_and_no_second_line_or_stderr(self):
        for out in (b'',b'A'*81,b'READY '+NONCE.encode()+b' '+b'0'*16+b' INAP00018\n',
                    b'READY '+b'0'*32+b' '+RECVRUN.encode()+b' INAP00018\n',
                    b'READY '+NONCE.encode()+b' '+RECVRUN.encode()+b' INAP00019\n'):
            with self.subTest(out=out):
                f=Wire();f.out=[out,b'']
                with self.assertRaises(w.Gate):f.run()
        for condition in ({'status':1},{'err':True},{'out':[Wire().expected+b'EXTRA\n',b'']}):
            with self.subTest(condition=condition):
                f=Wire();f.__dict__.update(condition)
                with self.assertRaises(w.Gate):f.run()
                self.assertEqual(len([x for x in f.log if isinstance(x,tuple) and x[0]=='request']),1)

if __name__=='__main__':
    with patch.object(socket,'create_connection',side_effect=AssertionError('real socket prohibited')):
        unittest.main(verbosity=2)
