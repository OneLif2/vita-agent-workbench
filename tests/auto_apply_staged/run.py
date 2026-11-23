"""Offline transport/ledger fixtures. Never connects, signs a production scope, or applies to Vita."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import auto_apply_staged as a

PIN="a"*64
PINF="d"*64
MAN="b"*64
BASE_RUN="1234567890ABCDEF"
BASE_BUILD="01.84-live-auto"
VER="01.84"
TARGET="01.85"
NONCE="C"*32
WBQ=f"WBQ2 {TARGET} {MAN} 31415"
COMMAND="r1-signed "+"0"*63+"1 "+"0"*63+"2"
APPLY="apply-return "+NONCE
NONE=f"r1 state=none source_run=- nonce=- target=- run={BASE_RUN} manifest=-"
GRANT=f"r1 state=authorized source_run={BASE_RUN} nonce={NONCE} target={TARGET} run={BASE_RUN} manifest={MAN}"
ARM=f"OK r1-signed target={TARGET} run={BASE_RUN} manifest={MAN} grant=armed"


class Probe:
    def __init__(self,records):
        self.transport_id="c"*64
        self.host_pin=PIN
        self.version=VER
        self.deadline=float("inf")
        self.commands=[]
        self.records=records
        self.runs=0
        self.armed=False
        self.apply_out=[a.ACK]
        self.arm_out=[ARM]
        self.state=None
        self.on_arm=None
        self.on_apply=None
        self.override={}
        self.identity=dict(channel="one interactive PTY",version=VER,run=BASE_RUN,build=BASE_BUILD,
                           host_sha256=PIN,transport_sha256=self.transport_id)
    def check(self):
        self.runs+=1
        return dict(self.identity)
    def rows(self,t,cmd):
        assert t is self
        self.commands.append(cmd)
        if cmd==COMMAND:
            assert not self.armed
            assert (self.records/"grant-issued.json").is_file()
            self.armed=True
            if self.on_arm:self.on_arm()
            return self.arm_out
        if cmd==APPLY:
            assert self.armed
            assert (self.records/"apply-issued.json").is_file()
            if self.on_apply:self.on_apply()
            return self.apply_out
        state=self.state
        fake=self.override.get(cmd)
        if fake is not None:
            return fake
        return {
            "pending":["pending-core: "+WBQ],
            "r1-status":[state or (GRANT if self.armed else NONE)],
            "r1-auto-status":[f"r1-auto state=enabled run={BASE_RUN}"],
            "updater check":["OK updater-check title=INAP00019 helper=reuse epoch=01.73 promote=0"],
            "ext sys":["payload online=1","payload battery=86","payload temp_c=24"],
        }[cmd]


class Rules(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.plan=a.Plan(dict(source_run=BASE_RUN,source_version=VER,host_sha256=PIN,manifest_sha256=MAN,
                              target=TARGET,wbq2=WBQ),COMMAND,BASE_BUILD,"e"*64,Path(d.name)/"fresh-ledger")
        self.t=Probe(self.plan.records)
    def go(self,trust=lambda:(PIN,PINF)):
        return a.issue(self.plan,paired=lambda:contextlib.nullcontext(self.t),trust=trust,rows=self.t.rows)
    def test_all_gates_before_two_precisely_once_operations(self):
        rc,j=self.go()
        self.assertEqual((rc,j["status"],j["installed"]),(0,"SUBMITTED_NOT_VERIFIED",False))
        self.assertEqual(self.t.commands,["pending","r1-auto-status","r1-status","updater check","ext sys",COMMAND,
                                        "r1-status","pending","r1-auto-status","r1-status","updater check","ext sys",APPLY])
        self.assertEqual(self.t.runs,3)
        self.assertEqual(set(x.name for x in self.plan.records.iterdir()),{"grant-issued.json","apply-issued.json","workflow.json"})
        self.assertEqual(json.loads((self.plan.records/"apply-issued.json").read_bytes())["grant"]["nonce"],NONCE)
        self.assertNotIn(COMMAND,(self.plan.records/"grant-issued.json").read_text(encoding="utf-8"))
    def test_wrong_original_pin_no_transport_or_write(self):
        with self.assertRaisesRegex(a.auth.Refused,"pin"):
            self.go(lambda:("f"*64,PINF))
        self.assertFalse(self.plan.records.exists())
        self.assertFalse(self.t.commands)
    def test_source_build_changed_never_writes_any_wire_verb(self):
        self.t.identity["build"]="01.84-other"
        self.assertEqual(self.go()[1]["status"],"NOT_SUBMITTED")
        self.assertFalse(self.t.commands)
        self.assertFalse((self.plan.records/"grant-issued.json").exists())
    def test_disabled_standing_no_signed_command(self):
        self.t.override["r1-auto-status"]=[f"r1-auto state=revoked run={BASE_RUN}"]
        self.assertEqual(self.go()[1]["status"],"NOT_SUBMITTED")
        self.assertNotIn(COMMAND,self.t.commands)
    def test_another_queue_is_not_treated_as_exact(self):
        self.t.override["pending"]=["pending-core: no"]
        self.assertEqual(self.go()[1]["status"],"NOT_SUBMITTED")
        self.assertNotIn(COMMAND,self.t.commands)
    def test_power_drop_after_arm_does_not_issue_apply(self):
        self.t.on_arm=lambda:self.t.override.update({"ext sys":["payload online=0","payload battery=86","payload temp_c=24"]})
        self.assertEqual(self.go()[1]["status"],"INCONCLUSIVE_NO_RETRY")
        self.assertIn(COMMAND,self.t.commands)
        self.assertNotIn(APPLY,self.t.commands)
    def test_wrong_arm_ack_stops_and_no_retry(self):
        self.t.arm_out=[ARM.replace(MAN,"f"*64)]
        self.assertEqual(self.go()[1]["status"],"SIGNED_GRANT_REFUSED_OR_UNCONFIRMED_NO_RETRY")
        with self.assertRaisesRegex(a.auth.Refused,"prior record"):
            self.go()
        self.assertEqual(self.t.commands.count(COMMAND),1)
        self.assertNotIn(APPLY,self.t.commands)
    def test_wrong_grant_scope_after_positive_arm_stops(self):
        self.t.on_arm=lambda:setattr(self.t,"state",GRANT.replace(f"target={TARGET}","target=01.86"))
        self.assertEqual(self.go()[1]["status"],"INCONCLUSIVE_NO_RETRY")
        self.assertNotIn(APPLY,self.t.commands)
    def test_lost_apply_ack_is_ambiguous_and_never_retried(self):
        def lost():
            raise EOFError("no prompt")
        self.t.on_apply=lost
        rc,result=self.go()
        self.assertEqual((rc,result["status"],result["installed"],result["apply_sent"]),(3,"INCONCLUSIVE_NO_RETRY",False,None))
        self.assertTrue((self.plan.records/"apply-issued.json").exists())
        with self.assertRaises(a.auth.Refused):self.go()
        self.assertEqual(self.t.commands.count(APPLY),1)
    def test_summary_missing_does_not_erase_issuance(self):
        original=a.flow.store
        def store(path,data):
            if path.name=="workflow.json":
                raise OSError("disk changed")
            return original(path,data)
        with patch.object(a.flow,"store",new=store):
            rc,result=self.go()
        self.assertEqual((rc,result["status"],result["summary_write_error"]),(0,"SUBMITTED_NOT_VERIFIED","OSError"))
        self.assertTrue((self.plan.records/"apply-issued.json").exists())
    def test_preview_no_socket_and_no_ledger(self):
        args="--profile p --profile-sha256 p --fingerprint p --stage s --vpk v --sha256 s --token t".split()
        with patch.object(a,"local_plan",return_value=self.plan),patch.object(a,"issue",side_effect=AssertionError("offline only")),contextlib.redirect_stdout(io.StringIO()) as o:
            rc=a.main(args)
        self.assertEqual((rc,json.loads(o.getvalue())["status"]),(0,"OFFLINE_PREVIEW"))
        self.assertFalse(self.plan.records.exists())


if __name__=="__main__":
    with patch.object(socket,"create_connection",side_effect=AssertionError("offline fixture: no socket")):
        unittest.main(verbosity=2)
