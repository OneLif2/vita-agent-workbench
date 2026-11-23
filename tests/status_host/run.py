"""Status CLI from a real WB Terminal parser and synthetic streams; no Vita/socket."""
from __future__ import annotations
import contextlib
import io
import json
import socket
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import status_client as s
import wbctl

PIN="a"*64
PINFILE="b"*64
SID="c"*64
RUN="1234567890ABCDEF"
ENDPOINT=(s.wb.HOST,str(s.wb.PORT),s.wb.USER)
NATIVE="01.86"
MAN="e"*64


def stdout(version=NATIVE):
    return (f"OK wb-status version={version} run={RUN} uptime_ms=66\n"
            "state wb=running lock=unknown overlay=yes foreground=blocked focus_reason=overlay\n"
            "network link=connected wifi=connected ssh_listener=listening ssh_session=paired\n"
            "update queue=pending target=01.87 standing=enabled\n"
            "END wb-status")


class Channel:
    def __init__(self,version=NATIVE,alter=lambda c,k,v:v):
        self.version=version
        self.alter=alter
        self.count=0
        self.exit_value=0
        self.seen=[]
        self.buf=bytearray(f"VITA AGENT TERMINAL {version} (Workbench)\r\nType help for commands.\r\nux0:/> ".encode())
    def sendall(self,b):
        cmd=b.decode("ascii").removesuffix("\n")
        self.seen.append(cmd)
        self.count+=1
        v=self.version
        examples={
            "ver":f"wb version={v} build={v}-live-status abi=3 proto=wb10 run={RUN} payload=none uptime_ms=70",
            "status":f"run={RUN} uptime_ms=70 ssh=connected cmds={self.count} payload=none core={v} last_install=none peer=127.0.0.1:2222",
            "wb-status":stdout(v),
            "pending":"pending-core: WBQ2 01.86 "+MAN+" 40000\n",
            "r1-auto-status":f"r1-auto state=enabled run={RUN}",
            "exit":"Bye.",
        }
        r=self.alter(cmd,self.seen.count(cmd),examples[cmd])
        self.buf.extend((cmd+"\n"+r+"\n"+("" if cmd=="exit" else "ux0:/> ")).replace("\n","\r\n").encode("ascii"))
    def recv(self,n):
        part=self.buf[:min(n,7)]
        del self.buf[:len(part)]
        return bytes(part)
    def recv_stderr_ready(self):return False
    def settimeout(self,_):pass
    def exit_status_ready(self):return self.seen[-1]=="exit" and not self.buf
    def recv_exit_status(self):return self.exit_value


class Cases(unittest.TestCase):
    def report(self,version=NATIVE,alter=lambda c,k,v:v,trust=lambda:(PIN,PINFILE),host=PIN,endpoint=ENDPOINT,exit_value=0):
        ch=Channel(version,alter)
        ch.exit_value=exit_value
        self.channel=ch
        t=s.wb.Terminal(ch,host,SID)
        calls=[]
        def paired(expected):
            calls.append(expected)
            return contextlib.nullcontext(t)
        rc,j=s.read_status(endpoint,paired=paired,trust=trust)
        self.assertLessEqual(len(calls),1)
        return rc,j
    def test_native_observed_with_noninferred_lock_and_all_fields(self):
        rc,r=self.report()
        self.assertEqual((rc,r["status"],r["source"],r["app_running"]),(0,"OBSERVED","native_wb_status",True))
        self.assertEqual((r["lock_screen"],r["system_overlay"],r["foreground_check"],r["focus_reason"]),
                         ("unknown","present","blocked","overlay"))
        self.assertEqual((r["network_link"],r["wifi"],r["ssh_listener"],r["ssh_session"]),("connected","connected","listening","paired"))
        self.assertEqual((r["wbq2_queue"],r["wbq2_target"],r["standing_update"]),("pending","01.87","enabled"))
        self.assertEqual(self.channel.seen,["ver","status","ver","wb-status","ver","status","ver","ver","exit"])
    def test_legacy_live_01_85_no_native_or_os_inference(self):
        rc,r=self.report("01.85")
        self.assertEqual((rc,r["source"],r["app_running"],r["ssh_session"]),(0,"legacy_paired_status",True,"paired"))
        self.assertEqual([r[x] for x in ("lock_screen","network_link","wifi","foreground_check","system_overlay","ssh_listener")],["unknown"]*6)
        self.assertEqual((r["wbq2_queue"],r["wbq2_target"],r["standing_update"]),("pending","01.86","enabled"))
        self.assertNotIn("wb-status",self.channel.seen)
    def test_very_old_legacy_skip_known_unsupported_standing(self):
        rc,r=self.report("01.83")
        self.assertEqual((rc,r["standing_update"]),(0,"unknown"))
        self.assertNotIn("r1-auto-status",self.channel.seen)
    def test_legacy_unknown_standing_and_malformed_pending(self):
        alter=lambda c,k,v:{"r1-auto-status":"ERR unknown command; type help","pending":"pending-core: WBQ1 01.86"}.get(c,v)
        rc,r=self.report("01.85",alter=alter)
        self.assertEqual((rc,r["standing_update"],r["wbq2_queue"],r["wbq2_target"]),(0,"unknown","unknown",None))
    def test_no_legacy_fallback_when_new_core_reply_unknown_or_truncated(self):
        for reply in ("ERR wb-status no-pty","ERR unknown command; type help",stdout().removesuffix("END wb-status"),
                      stdout()+"\nextra"):
            with self.subTest(reply=reply):
                rc,r=self.report(alter=lambda c,k,v:reply if c=="wb-status" else v)
                self.assertEqual((rc,r["status"],r["app_running"]),(3,"APP_UNKNOWN",None))
                self.assertNotIn("pending",self.channel.seen)
    def test_native_mixed_run_invalid_states_or_ambiguous_bytes_rejected(self):
        for old,new in [(RUN,RUN[::-1]),("01.86","01.85"),("lock=unknown","lock=locked"),("target=01.87","target=-"),
                        ("queue=pending","queue=unknown"),("wifi=connected","wifi=unregulated"),
                        ("uptime_ms=66","uptime_ms=18446744073709551616"),("uptime_ms=66","uptime_ms=999"),
                        ("ssh_session=paired","ssh_session=unknown"),("overlay=yes","overlay=yes\x1b"),
                        ("link=connected","link=disconnected"),("target=01.87","target=01.86"),
                        ("foreground=blocked","foreground=ready")]:
            with self.subTest(old=old,new=new):
                rc,r=self.report(alter=lambda c,k,v:v.replace(old,new,1) if c=="wb-status" else v)
                self.assertEqual((rc,r["status"],r["lock_screen"]),(3,"APP_UNKNOWN","unknown"))
    def test_final_same_run_and_graceful_exit_required(self):
        rc,r=self.report(alter=lambda c,k,v:v.replace(RUN,RUN[::-1]) if (c,k)==("ver",5) else v)
        self.assertEqual((rc,r["app_running"]),(3,None))
        rc,r=self.report(exit_value=1)
        self.assertEqual((rc,r["status"]),(3,"APP_UNKNOWN"))
    def test_ambiguous_transport_does_not_claim_app_closed(self):
        for error,reason in [(ConnectionRefusedError,"tcp_refused"),(TimeoutError,"timeout"),(EOFError,"status_unconfirmed")]:
            calls=[]
            def fail(_):
                calls.append(True)
                raise error("do not print remote raw")
            with self.subTest(error=error):
                rc,j=s.read_status(ENDPOINT,paired=fail,trust=lambda:(PIN,PINFILE))
                self.assertEqual((rc,j["status"],j["reason"],j["app_running"]),(3,"APP_UNKNOWN",reason,None))
                self.assertEqual((j["wifi"],j["lock_screen"],j["ssh_listener"]),("unknown","unknown","unknown"))
                self.assertEqual(calls,[True])
                self.assertNotIn("remote raw",json.dumps(j))
    def test_refused_pins_and_endpoint_are_not_retried(self):
        with self.subTest("pin"):
            rc,j=self.report(host="d"*64)
            self.assertEqual((rc,j["reason"]),(78,"trust_refused"))
            self.assertFalse(self.channel.seen)
        with self.subTest("tamper"):
            reads=iter([(PIN,PINFILE),(PIN,"d"*64)])
            rc,j=self.report(trust=lambda:next(reads))
            self.assertEqual((rc,j["reason"]),(78,"trust_refused"))
        with self.subTest("alternate"):
            rc,j=s.read_status(("127.0.0.1","22","wrong"),trust=lambda:self.fail("pin should not be touched"),
                               paired=lambda _:self.fail("network should not be touched"))
            self.assertEqual((rc,j["reason"]),(78,"unpaired_endpoint"))
        with self.subTest("not paired"):
            def absent():raise s.wb.pin.PairError("not paired")
            rc,j=s.read_status(ENDPOINT,trust=absent,paired=lambda _:self.fail("network should not be touched"))
            self.assertEqual((rc,j["reason"]),(78,"trust_refused"))
    def test_cli_subcommand_and_global_json_flags_use_status_client_not_old_bridge(self):
        report=s.unknown("timeout")
        for argv in (["--json","status"],["status","--json"]):
            with (self.subTest(argv=argv), patch.object(s,"read_status",return_value=(3,report)) as api,
                  patch.object(wbctl,"ssh",side_effect=AssertionError("legacy status bridge forbidden")),
                  contextlib.redirect_stdout(io.StringIO()) as out):
                rc=wbctl.main(argv)
                self.assertEqual((rc,json.loads(out.getvalue())),(3,report))
                api.assert_called_once_with(ENDPOINT)
    def test_real_paired_connector_rejects_wrong_host_before_loading_owner(self):
        import paramiko
        from types import SimpleNamespace
        class Transport:
            def __init__(self,_):pass
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def start_client(self,**_):pass
            def get_remote_server_key(self):
                return SimpleNamespace(get_name=lambda:s.wb.pin.ALGO,asbytes=lambda:b"wrong receiver")
        with (patch.object(s.wb.pin,"canonical_saved",return_value=(None,PIN)),
              patch.object(s.wb.socket,"create_connection",return_value=contextlib.nullcontext(None)),
              patch.object(paramiko,"Transport",Transport),
              patch.object(paramiko.ECDSAKey,"from_private_key_file",side_effect=AssertionError("owner key read")) as owner):
            rc,j=s.read_status(ENDPOINT,trust=lambda:(PIN,PINFILE))
        self.assertEqual((rc,j["status"],j["reason"]),(78,"APP_UNKNOWN","trust_refused"))
        owner.assert_not_called()


if __name__=="__main__":
    with patch.object(socket,"create_connection",side_effect=AssertionError("fixture: no real network")):
        unittest.main(verbosity=2)
