"""Ephemeral fixtures only. No Vita, registered identity or real trust store is used."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"tools"))
import pinned_check as pc
import wbctl
import wbterm

HOST="127.0.0.1"; PORT=2222
def fake_key(c):
    fields=(pc.ALGO.encode(),b"nistp256",b"\x04"+c*64)
    return b"".join(struct.pack(">I",len(v))+v for v in fields)
K1=fake_key(b"1"); K2=fake_key(b"2")
OLD=pc.digest(K1); NEW=pc.digest(K2)

class Store(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory(prefix="wb test "); self.addCleanup(d.cleanup)
        self.path=Path(d.name)/"store"/"device.known_hosts"
        self.calls=[]
    def pair(self,screen=OLD,old=None,remote=K1):
        def probe(h,p):
            self.calls.append((h,p));return remote
        return pc.pair(self.path,HOST,PORT,screen,old=old,observer=probe)
    def test_enroll_once(self):
        self.assertEqual(self.pair(),OLD); self.assertEqual(pc.saved_pin(self.path,HOST,PORT),OLD)
        self.assertEqual(self.path.read_text(),f"[127.0.0.1]:2222 {pc.ALGO} "+base64.b64encode(K1).decode()+"\n")
    def test_wrong_screen_no_pin(self):
        with self.assertRaisesRegex(pc.PairError,"screen fingerprint mismatch"):self.pair(remote=K2)
        self.assertFalse(self.path.exists()); self.assertEqual(list(self.path.parent.iterdir()),[])
    def test_no_unchecked_first_use(self):
        with self.assertRaisesRegex(pc.health.Problem,"invalid_screen_sha256"):self.pair("1234")
        self.assertFalse(self.path.exists()); self.assertEqual(self.calls,[])
    def test_enroll_never_replaces(self):
        self.pair()
        with self.assertRaisesRegex(pc.PairError,"already paired"):self.pair(NEW,remote=K2)
        self.assertEqual(pc.saved_pin(self.path,HOST,PORT),OLD); self.assertEqual(len(self.calls),1)
    def test_repair_requires_both(self):
        self.pair()
        with self.assertRaisesRegex(pc.PairError,"old fingerprint mismatch"):self.pair(NEW,"ab"*32,remote=K2)
        self.assertEqual(len(self.calls),1)
        with self.assertRaisesRegex(pc.PairError,"screen fingerprint mismatch"):self.pair(NEW,OLD,remote=K1)
        self.assertEqual(pc.saved_pin(self.path,HOST,PORT),OLD)
        self.assertEqual(self.pair(NEW,OLD,remote=K2), NEW)
    def test_corrupt_extra_entry_never_accepted(self):
        self.pair(); self.path.write_bytes(self.path.read_bytes()+b"* ssh-ed25519 invalid\n")
        with self.assertRaises(pc.PairError):pc.saved_pin(self.path,HOST,PORT)
        with self.assertRaises(pc.PairError):self.pair(NEW,OLD,remote=K2)
        self.assertEqual(len(self.calls),1)
    def test_endpoint_and_blob_validation(self):
        self.pair()
        with self.assertRaisesRegex(pc.PairError,"endpoint"):pc.saved_pin(self.path,HOST,2223)
        for blob in (b"",K1+b"x",K1[:-1],b"\xff"*80):
            with self.assertRaises(pc.PairError):pc.validate_blob(blob)
        with self.assertRaises(pc.PairError):pc.endpoint("8.8.8.8",2222)
    def test_lock_and_failure_never_replace(self):
        self.pair(); old=self.path.read_bytes()
        lock=self.path.with_suffix(".lock");lock.touch()
        with self.assertRaisesRegex(pc.PairError,"in progress"):self.pair(NEW,OLD,K2)
        self.assertEqual(self.path.read_bytes(),old);lock.unlink()
        with patch.object(pc.os,"replace",side_effect=OSError("fixture")):
            with self.assertRaises(OSError):self.pair(NEW,OLD,K2)
        self.assertEqual(self.path.read_bytes(),old);self.assertEqual(list(self.path.parent.iterdir()),[self.path])
    def test_unpaired_read_and_put_no_terminal_socket(self):
        with patch.object(pc,"pin_path",return_value=self.path), patch.object(socket,"create_connection") as conn:
            for cmd,data in (("ver",None),("put ux0:/VITA-POC/file 7 sha256="+pc.digest(b"fixture"),b"fixture")):
                self.assertEqual(wbctl.ssh(cmd,stdin_bytes=data)[0],78)
            conn.assert_not_called()
    def test_trust_change_stops_upgrade_poll(self):
        with patch.object(wbctl,"ssh",return_value=(78,"host key mismatch")) as f:
            self.assertEqual(wbctl.wait_for_version("01.30","T",5),("inconclusive","host key mismatch"))
            f.assert_called_once()
    def test_wbctl_refuses_alternative_endpoint_and_transport(self):
        with patch.object(wbctl,"HOST","192.168.99.99"),patch.object(socket,"create_connection") as conn:
            self.assertEqual(wbctl.ssh("ver")[0],78);conn.assert_not_called()
        with patch.object(wbterm,"paired_terminal") as tr:
            self.assertNotEqual(wbctl.ssh("exec ls")[0],0)
            self.assertNotEqual(wbctl.ssh("put fixture",stdin_bytes=b"fixture")[0],0)
            tr.assert_not_called()

    def test_check_uses_only_persisted_digest(self):
        self.pair()
        with patch.object(pc,"pin_path",return_value=self.path), patch.object(pc.health,"measure",return_value={"result":"PASS"}) as m:
            with contextlib.redirect_stdout(io.StringIO()) as s:
                self.assertEqual(pc.main(["--host",HOST,"--port",str(PORT),"check","--key","dummy"]),0)
            self.assertEqual(json.loads(s.getvalue())["result"],"PASS")
            m.assert_called_once_with(HOST,OLD,Path("dummy"),case="core",port=PORT)
    def test_store_python_redirected_trust_must_use_validated_physical_file(self):
        physical=self.path.parent/"LocalCache"/"Local"/"physical.known_hosts"
        physical.parent.mkdir(parents=True)
        pc.pair(physical,HOST,PORT,OLD,observer=lambda *_:K1)
        native_resolve=type(self.path).resolve
        def resolve(logical,strict=False):
            if logical==self.path:
                self.assertTrue(strict);return physical
            return native_resolve(logical,strict=strict)
        with patch.object(pc,"pin_path",return_value=self.path),patch.object(type(self.path),"resolve",resolve):
            with patch.object(pc,"observe",return_value=K1),contextlib.redirect_stdout(io.StringIO()) as s:
                self.assertEqual(pc.main(["--host",HOST,"enroll","--screen-fingerprint",OLD]),0)
            self.assertEqual(json.loads(s.getvalue())["path"],str(physical))
            with contextlib.redirect_stdout(io.StringIO()) as s:
                self.assertEqual(pc.main(["--host",HOST,"show"]),0)
            self.assertEqual(json.loads(s.getvalue())["path"],str(physical))
            argv=pc.openssh_argv(HOST,PORT,"fixture-owner","pi")
            self.assertIn(f'UserKnownHostsFile="{physical.as_posix()}"',argv)
            self.assertNotIn(f'UserKnownHostsFile="{self.path.as_posix()}"',argv)
            pc.pair(physical,HOST,PORT,NEW,old=OLD,observer=lambda *_:K2)
            with self.assertRaisesRegex(pc.PairError,"resolved pin differs"):
                pc.openssh_argv(HOST,PORT,"fixture-owner","pi")


@unittest.skipUnless(shutil.which("ssh"),"OpenSSH missing")
class Interop(unittest.TestCase):
    def test_real_pair_without_auth_then_two_independent_strict_clients(self):
        try: import paramiko
        except ImportError: self.skipTest("paramiko missing")
        import queue
        hk=paramiko.ECDSAKey.generate(); owner=paramiko.ECDSAKey.generate()
        server=socket.socket();self.addCleanup(server.close);server.bind((HOST,0));server.listen(2);server.settimeout(5)
        port=server.getsockname()[1];events=[];errors=[]
        class Server(paramiko.ServerInterface):
            def __init__(self,idx,q):self.idx=idx;self.q=q
            def get_allowed_auths(self,user):return 'publickey'
            def check_auth_none(self,user):events.append((self.idx,'auth-none'));return paramiko.AUTH_FAILED
            def check_auth_publickey(self,user,k):
                events.append((self.idx,"auth-pubkey"));return paramiko.AUTH_SUCCESSFUL if user=="pi" and k==owner else paramiko.AUTH_FAILED
            def check_channel_request(self,kind,cid):return paramiko.OPEN_SUCCEEDED if kind=="session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_pty_request(self,ch,term,width,height,pw,ph,modes):
                events.append((self.idx,"pty"));return term==b"vt100" and (width,height)==(80,24)
            def check_channel_shell_request(self,ch):
                events.append((self.idx,"shell"));self.q.put("shell");return True
            def check_channel_exec_request(self,ch,cmd):
                errors.append("forbidden exec");return False
            def check_channel_subsystem_request(self,ch,name):
                errors.append("forbidden subsystem");return False
        def serve():
            try:
                for idx in range(3):
                    with server.accept()[0] as s, paramiko.Transport(s) as t:
                        events.append((idx,"tcp"));t.add_server_key(hk)
                        q=queue.Queue()
                        if idx==0:
                            # Pairing intentionally closes just after reading the KEX key.
                            # WinSock can deliver the RST before start_server returns.
                            # pc.pair still has to validate the actual key, and this socket must never authenticate.
                            try:t.start_server(server=Server(idx,q));t.join(4)
                            except (EOFError,ConnectionResetError):pass
                            continue
                        t.start_server(server=Server(idx,q))
                        ch=t.accept(5);q.get(timeout=5);ch.settimeout(5)
                        ch.sendall(b"VITA AGENT TERMINAL 01.76 (Workbench)\r\nType help for commands.\r\nux0:/> ")
                        wire=ch.makefile("rb")
                        assert wire.readline()==b"ver\n"
                        ch.sendall(b"ver\r\nfixture-ver\r\nux0:/> ")
                        assert wire.readline()==b"exit\n"
                        ch.sendall(b"exit\r\nBye.\r\n");ch.send_exit_status(0);ch.close();t.join(4)
            except Exception as e:errors.append(repr(e))
        w=threading.Thread(target=serve,daemon=True)
        with tempfile.TemporaryDirectory(prefix="wb trust positive ") as d:
            p=Path(d)/"trust file"; dummy=Path(d)/"fixture-owner";owner.write_private_key_file(str(dummy))
            if os.name=="nt":
                import csv
                who=subprocess.check_output(["whoami","/user","/fo","csv","/nh"],text=True)
                sid=next(csv.reader([who.strip()]))[1]
                subprocess.run(["icacls",str(dummy),"/inheritance:r","/grant:r","*"+sid+":(F)"],check=True,capture_output=True)
            else:dummy.chmod(0o600)
            w.start()
            self.assertEqual(pc.pair(p,HOST,port,pc.digest(hk.asbytes())),pc.digest(hk.asbytes()))
            with patch.object(pc,"pin_path",return_value=p),patch.object(wbctl,"HOST",HOST),patch.object(wbctl,"PORT",port),patch.object(wbterm,"HOST",HOST),patch.object(wbterm,"PORT",port),patch.dict(os.environ,{"WB_KEY":str(dummy)}):
                for _ in range(2):self.assertEqual(wbctl.ssh("ver",timeout=6),(0,"fixture-ver"),(errors,events))
            w.join(5)
            self.assertFalse(w.is_alive());self.assertEqual(errors,[]);self.assertEqual([v for i,v in events if i==0],["tcp"])
            for idx in (1,2):
                self.assertIn((idx,"auth-pubkey"),events);self.assertEqual([v for i,v in events if i==idx and v in ("pty","shell")],["pty","shell"])
    def test_effective_openssh_configuration_offline(self):
        with tempfile.TemporaryDirectory(prefix="wb with spaces ") as d:
            p=Path(d)/"known_hosts"
            pc.pair(p,HOST,PORT,OLD,observer=lambda *_:K1)
            with patch.object(pc,"pin_path",return_value=p):
                argv=pc.openssh_argv(HOST,PORT,"dummy_key","pi");argv.insert(1,"-G")
                args=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True).stdout
            self.assertIn(f"userknownhostsfile {p.as_posix()}",args)
            self.assertRegex(args,r"stricthostkeychecking (yes|true)\b");self.assertIn("globalknownhostsfile none",args)
    def test_changed_key_stops_before_auth_real_pty_client_loopback(self):
        try: import paramiko
        except ImportError: self.skipTest("paramiko missing")
        paired=paramiko.ECDSAKey.generate()
        presented=paramiko.ECDSAKey.generate()
        server=socket.socket();self.addCleanup(server.close);server.bind((HOST,0));server.listen(1);server.settimeout(5)
        port=server.getsockname()[1];auth=[];accepted=[]
        class RejectServer(paramiko.ServerInterface):
            def get_allowed_auths(self,user):auth.append(user);return "publickey"
            def check_auth_none(self,user):auth.append(user);return paramiko.AUTH_FAILED
            def check_auth_publickey(self,user,k):auth.append(user);return paramiko.AUTH_FAILED
        def serve():
            with server.accept()[0] as s:
                accepted.append(True)
                with paramiko.Transport(s) as t:
                    t.add_server_key(presented)
                    try:t.start_server(server=RejectServer());t.join(4)
                    except (EOFError,OSError,paramiko.SSHException):pass
        w=threading.Thread(target=serve,daemon=True)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fixture-known-hosts";dummy=Path(d)/"fixture-owner"
            pc.pair(p,HOST,port,pc.digest(paired.asbytes()),observer=lambda *_:paired.asbytes())
            paramiko.ECDSAKey.generate().write_private_key_file(str(dummy))
            envpatch=(patch.object(pc,"pin_path",return_value=p),patch.object(wbctl,"HOST",HOST),
                      patch.object(wbctl,"PORT",port),patch.object(wbterm,"HOST",HOST),patch.object(wbterm,"PORT",port),patch.dict(os.environ,{"WB_KEY":str(dummy)}))
            with contextlib.ExitStack() as stack:
                for cm in envpatch:stack.enter_context(cm)
                w.start()
                rc,out=wbctl.ssh("ver", timeout=5)
                w.join(5)
            self.assertEqual(rc,78,out);self.assertFalse(w.is_alive());self.assertEqual(accepted,[True])
            self.assertEqual(auth,[]);self.assertEqual(pc.saved_pin(p,HOST,port),pc.digest(paired.asbytes()))


if __name__=="__main__":unittest.main(verbosity=2)
