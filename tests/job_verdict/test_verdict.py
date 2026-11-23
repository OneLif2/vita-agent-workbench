"""Test host job verdicts using the approved package and simulated replies. No device or network."""
import contextlib,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/"tools"))
import wbctl as w
sys.path.insert(0,str(R/"tests"))
from native_identity import VERSION, BUILD
# The 01.54 signed-off VPK remains the approved TestApp in this release.
# The tests use the same title/version/hash admission as the real command.
APP=R/"build/testapp.vpk"
if not APP.is_file():APP=R.parent/"v1.54/build/testapp.vpk"

A="1111111111111111"; B="2222222222222222"; C="3333333333333333"
def ver(run):return f"wb version={VERSION} build={BUILD} abi=3 proto=wb10 run={run} payload=none uptime_ms=123"

class Verdict(unittest.TestCase):
    def go(self, *, edits=None, raw_edit=None, launch_rc=0, launch_override=None, ret=B, post=B, before=A,
           get_rc=0,case="fs-smoke",rc_expected=0,ver_fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);state={"ver":0,"job":None};cmds=[]
            def cmd(query,**kwargs):
                cmds.append(query)
                if query=="ver":
                    n=state["ver"];state["ver"]+=1
                    if n==1 and ver_fail:return 78,"ERR SSH host key verification failed"
                    return 0,ver([before,ret,post][n])
                if query.startswith("launch "):
                    state["job"]=query.split()[-1]
                    return launch_rc,(launch_override if launch_override is not None else
                        f"OK launch title=INAP00020 case={case} job={state['job']}")
                self.assertEqual(query,"get ux0:data/INAP00018/testapp/result.txt")
                fields={"job":state["job"],"title":"INAP00020","build":"01.01-testapp","case":case,
                        "assert":{"fs-smoke":"write=64 read=64 match=1","compute-smoke":"fnv1a=0x655C5FFD expected=0x655C5FFD","power-smoke":"battery=88 temp_raw=3125"}[case],"result":"PASS"}
                fields.update(edits or {})
                raw="\n".join(f"{k}={v}" for k,v in fields.items())
                return get_rc,(raw_edit(raw) if raw_edit else raw)
            with patch.object(w,"ssh",side_effect=cmd),patch.object(w,"JOBS_DIR",d),contextlib.redirect_stdout(io.StringIO()):
                rc=w.main(["test","run",case,"--vpk",str(APP),"--timeout","1"])
            self.assertEqual(rc,rc_expected)
            files=list(d.glob("*.json"));self.assertEqual(len(files),1)
            doc=json.loads(files[0].read_text());texts=list(d.glob("*.txt"));raw=texts[0].read_text() if texts else None
            self.assertLessEqual(sum(c.startswith("launch ") for c in cmds),1)
            return doc,raw,cmds

    def test_positive_case_oracle(self):
        for case in ["fs-smoke","compute-smoke","power-smoke"]:
            with self.subTest(case=case):
                d,raw,cmds=self.go(case=case);self.assertEqual(d["result"],"PASS");self.assertIn(d["job"],raw)
                self.assertEqual((d["run_before"],d["run_after"]),(A,B))
                self.assertEqual(cmds.count("ver"),3)
    def test_wrong_claim_never_persists_pass(self):
        for edits in [{"job":"stale"},{"title":"INAP00021"},{"case":"compute-smoke"},{"build":"02.00-testapp"},
                      {"assert":"anything"},{"assert":"write=64 read=0 match=0"},{"result":"PASS PASS"}]:
            with self.subTest(edits=edits):
                d,raw,_=self.go(edits=edits,rc_expected=7);self.assertEqual(d["result"],"INCONCLUSIVE")
                self.assertIsNotNone(raw)
    def test_duplicate_missing_empty_extra(self):
        for edit in [lambda raw:raw+"\nresult=PASS",lambda raw:raw.replace("title=INAP00020\n",""),
                     lambda raw:raw.replace("build=01.01-testapp","build="),lambda raw:raw+"\nextra=1",
                     lambda raw:raw.replace("\n", "\x0b", 1)]:
            d,_,_=self.go(raw_edit=edit,rc_expected=7);self.assertEqual(d["result"],"INCONCLUSIVE")
    def test_known_failure_not_promoted(self):
        d,raw,_=self.go(edits={"assert":"write=64 read=4 match=0","result":"FAIL"},rc_expected=1)
        self.assertEqual((d["result"],d["device_claimed_result"]),("FAIL","FAIL"));self.assertIn("read=4",raw)
    def test_power_range_compute_digest(self):
        for case,detail in [("compute-smoke","fnv1a=0x12345678 expected=0x12345678"),("power-smoke","battery=101 temp_raw=3000")]:
            d,_,_=self.go(case=case,edits={"assert":detail},rc_expected=7);self.assertEqual(d["result"],"INCONCLUSIVE")
    def test_explicit_negative_or_pin_stops(self):
        for rc,txt,exit_code in [(1,"ERR registry-case",4),(255,"ERR app-launch rc=0x01",4),
                                 (78,"ERR SSH host key verification failed",7),(0,"OK launch but wrong job",7)]:
            d,_,cmds=self.go(launch_rc=rc,launch_override=txt,rc_expected=exit_code);self.assertEqual(len(cmds),2)
            self.assertNotEqual(d["result"],"PASS")
    def test_dropped_ack_does_not_relaunch(self):
        for rc in [124,255]:
            d,_,cmds=self.go(launch_rc=rc,launch_override="connection dropped");self.assertEqual(d["result"],"PASS")
            self.assertEqual(d["launch_state"],"unknown-after-timeout-or-disconnect")
            self.assertEqual(sum(i.startswith("launch ") for i in cmds),1)
    def test_no_downgrade_when_changed_host_key(self):
        d,_,cmds=self.go(ver_fail=True,rc_expected=7); self.assertEqual(d["reason"],"returned-host-trust-failed")
        self.assertFalse(any(c.startswith("get ") for c in cmds))
    def test_no_result_and_post_read_run_changed(self):
        d,_,_=self.go(get_rc=1,rc_expected=7);self.assertEqual(d["reason"],"result-read-failed")
        d,_,_=self.go(post=C,rc_expected=7);self.assertEqual(d["reason"],"core-changed-during-result-read")
    def test_before_wrong_core_build_no_launch(self):
        with patch.object(w,"ssh",return_value=(0,ver(A).replace(BUILD,"01.30-live-storage1"))) as sock, tempfile.TemporaryDirectory() as t, patch.object(w,"JOBS_DIR",Path(t)),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(["test","run","fs-smoke","--vpk",str(APP)]),7)
            self.assertEqual(sock.call_count,1)
    def test_requires_new_run(self):
        with tempfile.TemporaryDirectory() as t,patch.object(w,"JOBS_DIR",Path(t)),contextlib.redirect_stdout(io.StringIO()):
            def fake(c,**kw):
                if c=="ver":return 0,ver(A)
                if c.startswith("launch "): return 124,"TIMEOUT"
                self.fail("unexpected write/read after unchanged run")
            with patch.object(w,"ssh",side_effect=fake) as x:
                self.assertEqual(w.main(["test","run","fs-smoke","--vpk",str(APP),"--timeout","1"]),7)
            d=json.loads(next(Path(t).glob("*.json")).read_text());self.assertEqual(d["reason"],"no-new-workbench-run-before-deadline")
            self.assertEqual(sum(e.args[0].startswith("launch ") for e in x.call_args_list),1)

if __name__=="__main__":unittest.main(verbosity=2)
