"""Host tests only. Never targets a Vita. TestWire listens only on loopback with generated keys."""
import hashlib
import importlib.util
import logging
import os
from pathlib import Path
import queue
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("check_in_place",ROOT/"tools/check_in_place.py")
wc=importlib.util.module_from_spec(spec);spec.loader.exec_module(wc)
sys.path.insert(0,str(ROOT/"tests"))
from native_identity import VERSION, BUILD
V=f"wb version={VERSION} build={BUILD} abi=3 proto=wb10 run=ABCDEF0123456789 payload=none uptime_ms="
S=f"run=ABCDEF0123456789 uptime_ms=110 ssh=connected cmds=2 payload=none core={VERSION} last_install=none peer=127.0.0.1:2222"
ROWS=[V+"100",S,V+"120"]
SID=b"synthetic session id"
KEY=b"synthetic wire key"
PIN=hashlib.sha256(KEY).hexdigest()

class FakeKey:
    def get_name(self):return "ecdsa-sha2-nistp256"
    def asbytes(self):return KEY

class Sock:
    def __enter__(self):return self
    def __exit__(self,*exc):pass

class Ch:
    def __init__(self,tr):self.t=tr;self.closed=False
    def settimeout(self,n):pass
    def exec_command(self,cmd):
        self.t.commands.append(cmd);i=len(self.t.commands)-1
        if self.t.raise_at==i:raise OSError('synthetic disconnect')
        s=self.t.rows[i]
        self.out=s.encode()+b'\n' if isinstance(s,str) else s
    def recv_ready(self):return bool(self.out)
    def recv_stderr_ready(self):return bool(self.t.err)
    def recv(self,n):
        a,self.out=self.out[:n],self.out[n:]
        if not self.out:self.closed=True
        return a
    def exit_status_ready(self):return self.t.exit is not None
    def recv_exit_status(self):return self.t.exit
    def close(self):self.closed=True

class Tr:
    def __init__(self,rows): self.rows=rows;self.auth=0;self.commands=[];self.closes=0;self.allow_auth=True;self.session_id=SID;self.raise_at=-1;self.exit=0;self.err=False
    def start_client(self,timeout):pass
    def get_remote_server_key(self):return FakeKey()
    def auth_publickey(self,user,key):self.auth+=1
    def is_authenticated(self):return self.auth==1 and self.allow_auth
    def is_active(self):return self.closes==0
    def open_session(self,timeout):return Ch(self)
    def close(self):self.closes+=1

class TestCheck(unittest.TestCase):
    def setUp(self):
        self.tr=Tr(ROWS.copy());self.opens=0;self.keys=0
    def measure(self,pin=PIN,host="127.0.0.1",case="core"):
        def open_sock(*a,**kw):self.opens+=1;return Sock()
        def load(path):self.keys+=1;return object()
        return wc.measure(host,pin,Path("no-owner-file-used"),case=case,open_socket=open_sock,transport_factory=lambda s:self.tr,owner_key_loader=load)
    def test_01_same_transport(self):
        v=self.measure();self.assertEqual(v['result'],'PASS');self.assertEqual(v['transport_sha256'],hashlib.sha256(SID).hexdigest());self.assertEqual(self.tr.commands,list(wc.COMMANDS));self.assertEqual(self.opens,1);self.assertEqual(self.tr.closes,1)
    def test_02_invalid_pin_no_socket(self):
        with self.assertRaisesRegex(wc.Problem,'invalid_screen'):self.measure('12')
        self.assertEqual(self.opens,0)
    def test_03_bad_pin_no_private_key_or_auth(self):
        with self.assertRaisesRegex(wc.Problem,'screen_host_key_mismatch'):self.measure('0'*64)
        self.assertEqual((self.opens,self.keys,self.tr.auth,self.tr.commands),(1,0,0,[]))
    def test_04_refuse_host_input_before_connect(self):
        for h in ("0.0.0.0","224.0.0.1","example.com","8.8.8.8"):
            with self.assertRaises(wc.Problem): self.measure(host=h)
        self.assertEqual(self.opens,0)
    def test_05_owner_denied(self):
        self.tr.allow_auth=False
        with self.assertRaisesRegex(wc.Problem,'owner_auth_failed'):self.measure()
        self.assertEqual(self.tr.commands,[])
    def test_06_wrong_build_stops_after_one_command(self):
        self.tr.rows[0]=self.tr.rows[0].replace(BUILD,"01.24-old")
        with self.assertRaisesRegex(wc.Problem,'unexpected_core_identity'):self.measure()
        self.assertEqual(self.tr.commands,['ver'])
    def test_07_other_run_is_not_a_pass(self):
        self.tr.rows[2]=self.tr.rows[2].replace("ABCDEF","FFFFFF")
        with self.assertRaisesRegex(wc.Problem,'run_payload_or_core_changed'):self.measure()
    def test_08_other_payload_is_not_a_pass(self):
        self.tr.rows[1]=S.replace('payload=none','payload=01.22-p2.1')
        with self.assertRaisesRegex(wc.Problem,'run_payload_or_core_changed'):self.measure()
    def test_09_bad_uptime_is_not_a_pass(self):
        self.tr.rows[1]=S.replace('uptime_ms=110','uptime_ms=80')
        with self.assertRaisesRegex(wc.Problem,'uptime_not_progressing'):self.measure()
    def test_10_changed_status_shape_rejected(self):
        self.tr.rows[1]=S+' unreviewed=1'
        with self.assertRaisesRegex(wc.Problem,'unexpected_status_format'):self.measure()
    def test_11_drop_no_retry(self):
        self.tr.raise_at=1
        with self.assertRaises(OSError):self.measure()
        self.assertEqual(self.opens,1);self.assertEqual(self.tr.commands,['ver','status'])
    def test_12_bounded_reply(self):
        self.tr.rows[0]=b'X'*2100
        with self.assertRaisesRegex(wc.Problem,'reply_too_large'):self.measure()
    def test_13_no_missing_exit(self):
        self.tr.exit=None
        with self.assertRaisesRegex(wc.Problem,'nonzero_or_missing_exit'):self.measure()
    def test_14_stderr_rejected(self):
        self.tr.err=True
        with self.assertRaisesRegex(wc.Problem,'remote_stderr'):self.measure()
    def test_15_multiple_lines_rejected(self):
        self.tr.rows[0]+='\npayload=something'
        with self.assertRaisesRegex(wc.Problem,'not_one_result_line'):self.measure()

    def power_rows(self):
        sysout=("payload sys version=01.22-p2.1\npayload abi=3\npayload uptime_ms=115"
                "\npayload battery=89\npayload temp_c=30\npayload charging=0\npayload online=1")
        a,b,c=[row.replace("payload=none","payload=01.22-p2.1") for row in ROWS]
        return [a,b,sysout,c]
    def test_16_power_active_only(self):
        self.tr.rows=self.power_rows()
        result=self.measure(case='power')
        self.assertEqual(result['power'],dict(battery_percent=89,temperature_c=30,charging=False,online=True))
        self.assertEqual(self.tr.commands,['ver','status','ext sys','ver']);self.assertEqual(self.opens,1)
    def test_17_power_does_not_lazy_load(self):
        with self.assertRaisesRegex(wc.Problem,'already_active_payload'):self.measure(case='power')
        self.assertEqual(self.tr.commands,['ver'])
    def test_18_power_precheck_stops_before_ext_sys_when_status_differs(self):
        self.tr.rows=self.power_rows();self.tr.rows[1]=S
        with self.assertRaisesRegex(wc.Problem,'run_payload_or_core_changed'):self.measure(case='power')
        self.assertEqual(self.tr.commands,['ver','status'])
    def test_19_power_rejects_unavailable(self):
        self.tr.rows=self.power_rows();self.tr.rows[2]=self.tr.rows[2].replace('temp_c=30','temp_c=unavailable')
        with self.assertRaisesRegex(wc.Problem,'power_reading_unavailable'):self.measure(case='power')
    def test_20_power_rejects_impossible_battery_percentage(self):
        self.tr.rows=self.power_rows();self.tr.rows[2]=self.tr.rows[2].replace('battery=89','battery=101')
        with self.assertRaisesRegex(wc.Problem,'power_reading_unavailable'):self.measure(case='power')
    def test_21_power_rejects_impossible_temperature(self):
        self.tr.rows=self.power_rows();self.tr.rows[2]=self.tr.rows[2].replace('temp_c=30','temp_c=3015')
        with self.assertRaisesRegex(wc.Problem,'power_reading_unavailable'):self.measure(case='power')
    def test_22_power_rejects_truncated_response(self):
        self.tr.rows=self.power_rows();self.tr.rows[2]=self.tr.rows[2].split('\npayload temp_c')[0]
        with self.assertRaisesRegex(wc.Problem,'unexpected_power_format'):self.measure(case='power')
    def test_23_power_rejects_old_reading(self):
        self.tr.rows=self.power_rows();self.tr.rows[2]=self.tr.rows[2].replace('uptime_ms=115','uptime_ms=30')
        with self.assertRaisesRegex(wc.Problem,'power_uptime_not_in_run'):self.measure(case='power')
    def test_24_power_confirms_same_run_after_ext(self):
        self.tr.rows=self.power_rows();self.tr.rows[3]=self.tr.rows[3].replace('ABCDEF','FFFFFF')
        with self.assertRaisesRegex(wc.Problem,'run_payload_or_core_changed'):self.measure(case='power')

try:
    import paramiko
except ImportError:
    paramiko=None

@unittest.skipIf(paramiko is None,"Paramiko absent: localhost wire test NOT run")
class TestWire(unittest.TestCase):
    def test_real_pinned_loopback_ecdsa_three_execs_one_connection(self):
        # No real owner credentials; this listener accepts only the ephemeral test key.
        hk=paramiko.ECDSAKey.generate();uk=paramiko.ECDSAKey.generate()
        commandq=queue.Queue(); seen=[]; texts=[];errors=[]
        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self,username):return 'publickey'
            def check_auth_publickey(self,username,k):
                seen.append(('auth',username))
                return paramiko.AUTH_SUCCESSFUL if username=='pi' and k==uk else paramiko.AUTH_FAILED
            def check_channel_request(self,kind,chanid):
                return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_exec_request(self,chan,command):
                if command not in (b'ver',b'status'):return False
                commandq.put((chan.get_id(),command));return True
        server=socket.socket();self.addCleanup(server.close);server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(4)
        release=threading.Event()
        def work():
            t=None
            try:
                with server.accept()[0] as s:
                    seen.append(('accepted',1))
                    t=paramiko.Transport(s);t.add_server_key(hk);t.start_server(server=Server())
                    for text in ROWS:
                        ch=t.accept(4);assert ch is not None
                        cid,command=commandq.get(timeout=4);assert ch.get_id()==cid
                        texts.append(command.decode());time.sleep(.025);ch.sendall(text+'\n');ch.send_exit_status(0);ch.close()
                    release.wait(4)
            except Exception as e:errors.append(repr(e))
            finally:
                if t:t.close()
        worker=threading.Thread(target=work,daemon=True);worker.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                key=Path(d)/'ephemeral_owner_key';uk.write_private_key_file(str(key));report=wc.measure('127.0.0.1',hashlib.sha256(hk.asbytes()).hexdigest(),key,port=server.getsockname()[1])
            self.assertEqual(report['result'],'PASS')
        finally:release.set();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[]);self.assertEqual(seen,[('accepted',1),('auth','pi')]);self.assertEqual(texts,['ver','status','ver'])

if __name__=="__main__":unittest.main(verbosity=2)

