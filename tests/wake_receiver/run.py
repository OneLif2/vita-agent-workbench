"""Real Paramiko loopback, synthetic Vita state, and no physical device I/O."""
import contextlib,socket,sys,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
import paramiko,wake_receiver as x

NONCE=b'0abcdef1234567890abcdef123456789'
REQ=b'READY '+NONCE+b'\n'
OPEN=b'OPEN '+NONCE+b'\n'
RUN='A70B14027201CCFF'
OK=b'READY '+NONCE+b' '+RUN.encode()+b' INAP00018\n'

class Tests(unittest.TestCase):
 def setUp(self):
  self.clock=0.0;self.att=0;self.works=True
  self.s=x.PlatformState(True,True,True,True)
  self.receiver=x.Receiver(RUN,lambda:self.s,self.launch,lambda:self.clock)
 def launch(self):self.att+=1;return self.works
 def close_app(self):self.s=x.PlatformState(True,True,True,False)
 def test_positive_single_use(self):
  self.receiver.enable_local()
  self.assertEqual(self.receiver.handle(REQ),(0,OK));self.assertEqual(self.att,0)
  self.assertEqual(self.receiver.handle(OPEN),(125,b'ALREADY_RUNNING\n'))
  self.close_app();self.assertEqual(self.receiver.handle(OPEN)[0],0)
  self.assertEqual(self.receiver.handle(OPEN)[0],126);self.assertEqual(self.att,1)
 def test_no_lease_no_probe_or_launch(self):
  self.assertEqual(self.receiver.handle(REQ)[0],126);self.assertEqual(self.receiver.handle(OPEN)[0],126)
  self.assertEqual(self.att,0)
 def test_no_title_or_second_message(self):
  self.receiver.enable_local()
  for raw in (REQ+b'shell\n',b'OPEN INAP00019\n',b'OPEN '+NONCE+b' INAP00019\n',REQ[:-1]+b'\x00\n',REQ[:-1]+b'\r\n'):
   self.assertEqual(self.receiver.handle(raw),(125,b'DENIED\n'))
  self.assertEqual(self.receiver.handle(REQ),(0,OK));self.assertEqual(self.att,0)
 def test_unknown_and_busy(self):
  self.receiver.enable_local()
  self.s=x.PlatformState(True,True,True,None);self.assertNotEqual(self.receiver.handle(REQ)[0],0)
  self.s=x.PlatformState(True,True,True,True);self.assertEqual(self.receiver.handle(REQ)[0],0)
  self.s=x.PlatformState(True,True,False,False);self.assertEqual(self.receiver.handle(OPEN)[0],125);self.assertEqual(self.att,0)
 def test_replay_wrong_expiration_revoke(self):
  self.receiver.enable_local();self.assertEqual(self.receiver.handle(REQ)[0],0)
  self.assertEqual(self.receiver.handle(REQ)[0],125)
  self.assertEqual(self.receiver.handle(b'OPEN '+b'9'*32+b'\n')[0],125)
  self.close_app();self.clock=60;self.assertEqual(self.receiver.handle(OPEN)[0],126)
  self.receiver.enable_local();self.receiver.handle(REQ)
  self.receiver.revoke_local();self.assertEqual(self.receiver.handle(OPEN)[0],126);self.assertEqual(self.att,0)
 def test_platform_error_spent(self):
  self.receiver.enable_local();self.receiver.handle(REQ);self.close_app();self.works=False
  self.assertEqual(self.receiver.handle(OPEN),(1,b'PLATFORM_ERROR\n'))
  self.assertEqual(self.receiver.handle(OPEN)[0],126);self.assertEqual(self.att,1)

 @contextlib.contextmanager
 def peer(self):
  server=paramiko.ECDSAKey.generate();owner=paramiko.ECDSAKey.generate()
  faults=[]
  with socket.socket() as listener:
   listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(4)
   def serve():
    try:
     sc,_=listener.accept()
     with sc:x.serve_loopback_once(sc,server,x.fp(owner),self.receiver)
    except (EOFError,ConnectionResetError):pass
    except Exception as e:faults.append(type(e).__name__+': '+str(e))
   th=threading.Thread(target=serve,daemon=True);th.start()
   try:
    with socket.create_connection(listener.getsockname(),timeout=3) as s, paramiko.Transport(s) as t:
     t.start_client(timeout=3)
     self.assertEqual(x.fp(t.get_remote_server_key()),x.fp(server)) # before owner auth
     yield t,owner
   finally:
    th.join(5);self.assertFalse(th.is_alive(),faults);self.assertFalse(faults)
 def test_ssh_fragmented_ready_on_exact_subsystem(self):
  self.receiver.enable_local()
  with self.peer() as (t,k):
   t.auth_publickey('pi',k)
   with t.open_session(timeout=2) as c:
    c.settimeout(4);c.invoke_subsystem('wb-wake-v1');c.sendall(REQ[:5]);c.sendall(REQ[5:]);c.shutdown_write()
    b=b''
    while chunk:=c.recv(128):b+=chunk
    self.assertEqual((c.recv_exit_status(),b),(0,OK))
  self.assertEqual(self.att,0)
 def test_ssh_wrong_owner_rejected(self):
  with self.peer() as (t,k):
   with self.assertRaises(paramiko.AuthenticationException):t.auth_publickey('pi',paramiko.ECDSAKey.generate())
  self.assertEqual(self.att,0)
 def test_ssh_no_exec_shell_pty_or_other_subsystem(self):
  for call in (lambda c:c.exec_command('wb open'),lambda c:c.invoke_shell(),lambda c:c.get_pty(),lambda c:c.invoke_subsystem('sftp')):
   with self.peer() as (t,k):
    t.auth_publickey('pi',k)
    c=t.open_session(timeout=2)
    with self.assertRaises(paramiko.SSHException):call(c)
  self.assertEqual(self.att,0)
if __name__=='__main__':unittest.main(verbosity=2)
