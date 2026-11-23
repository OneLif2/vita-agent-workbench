"""Offline signer/regression coverage; ephemeral in-memory fixture keys only, no owner key or Vita."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import auto_update_authorize as a
sys.path.insert(0,str(ROOT/'tests/stub'))
from self_fixture import fixture as core_fixture
import r1ctl
from cryptography.hazmat.primitives.asymmetric import ec

HOST="a"*64
OWNER="b"*64
SOURCE="01.84"
TARGET="01.85"
RUN="0123456789ABCDEF"
TX_BUILD=TARGET+"-live-future"


class Cases(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.d=Path(temp.name)
        self.key=ec.generate_private_key(ec.SECP256R1())
        self.sec1=a.public_sec1(self.key.public_key())
        self.p=self.d/"profile.json"
        self.fp=a.sha(self.sec1)
        self.fields=dict(schema=a.PROFILE_SCHEMA,host_sha256=HOST,owner_sha256=OWNER,
                         release_key_sha256=self.fp,release_key_sec1=self.sec1.hex())
        self.p.write_text(json.dumps(self.fields),encoding="utf-8")
        self.trust=a.load_profile(self.p,a.sha(self.p.read_bytes()),self.fp)
        self.scope=dict(title=a.TITLE,target=TARGET,source_version=SOURCE,manifest_sha256="c"*64)
        self.m=a.canonical(TARGET,"c"*64,31415,HOST,OWNER,SOURCE,RUN)
    def test_exact_canonical_message_includes_domain_run_and_both_pins(self):
        self.assertEqual(self.m,("WB-R1-AUTO-v1\nINAP00018 "+TARGET+" "+"c"*64+" 31415\n"
                                 +"HOST "+HOST+"\nOWNER "+OWNER+"\nSOURCE "+SOURCE+" "+RUN+"\n").encode("ascii"))
    def test_valid_low_s_signature_is_two_fixed_hex_words(self):
        token=a.sign_token(self.trust,self.scope,self.m,self.key)
        self.assertEqual(token["scope"],self.scope)
        self.assertFalse(token["sent"])
        self.assertTrue(a.verify_token(token,self.trust,self.scope,self.m))
        _,r,s=token["command"].split()
        self.assertEqual((len(r),len(s)),(64,64))
        self.assertLessEqual(int(s,16),a.P256_N//2)
    def test_all_mutations_cause_auth_failure(self):
        tok=a.sign_token(self.trust,self.scope,self.m,self.key)
        for old,new in [(a.DOMAIN,"WB-R1-AUTO-v2"),(a.TITLE,"INAP00019"),(TARGET,"01.86"),("c"*64,"d"*64),
                        ("31415","31416"),(HOST,"e"*64),(OWNER,"f"*64),(SOURCE,"01.83"),(RUN,RUN[::-1])]:
            with self.subTest(old=old), self.assertRaisesRegex(a.Refused,"signature does not authorize"):
                a.verify_token(tok,self.trust,self.scope,self.m.replace(old.encode(),new.encode(),1))
    def test_noncanonical_high_s_zero_and_extra_tokens(self):
        tok=a.sign_token(self.trust,self.scope,self.m,self.key)
        _,r,s=tok["command"].split()
        alternative=a.P256_N-int(s,16)
        for cmd in (f"r1-signed {r} {alternative:064x}",f"r1-signed {'0'*64} {s}",f"r1-signed {r} {s.upper()} extra",
                    f"r1-signed {r} {s}\n"):
            with self.subTest(cmd=cmd),self.assertRaises(a.Refused):
                a.verify_token(dict(tok,command=cmd),self.trust,self.scope,self.m)
    def test_run_and_version_not_replayable(self):
        for v,t,run in [(SOURCE,SOURCE,RUN),(SOURCE,"01.83",RUN),(SOURCE,TARGET,"0"*16),(SOURCE,TARGET,RUN.lower()),("01.84x",TARGET,RUN)]:
            with self.subTest(v=v,t=t,run=run),self.assertRaises(a.Refused):
                a.canonical(t,"c"*64,31415,HOST,OWNER,v,run)
    def test_stage_size_type_and_range_fail_closed(self):
        for n in (True,0,-1,a.MAX_STAGE+1,"31415","031415",31.415):
            with self.subTest(n=n),self.assertRaises(a.Refused):
                a.canonical(TARGET,"c"*64,n,HOST,OWNER,SOURCE,RUN)
    def test_key_mismatch_and_other_curve_are_refused(self):
        for other in (ec.generate_private_key(ec.SECP256R1()),ec.generate_private_key(ec.SECP384R1())):
            with self.assertRaises(a.Refused):
                a.sign_token(self.trust,self.scope,self.m,other)
    def test_profile_and_independent_fingerprint_pins(self):
        h=a.sha(self.p.read_bytes())
        for sha,fp in [(h,"e"*64),("f"*64,self.fp)]:
            with self.assertRaises(a.Refused):
                a.load_profile(self.p,sha,fp)
    def test_distinct_release_key_not_ssh_key_under_different_fp_domain(self):
        for field in ("host_sha256","owner_sha256"):
            x=dict(self.fields,**{field:a.ssh_owner_fingerprint(self.sec1)})
            self.p.write_text(json.dumps(x),encoding="utf8")
            with self.subTest(field=field),self.assertRaisesRegex(a.Refused,"must differ"):
                a.load_profile(self.p,a.sha(self.p.read_bytes()),self.fp)
    def test_bad_sec1_and_profile_duplicate_fields_fail(self):
        for body in (json.dumps(dict(self.fields,release_key_sec1="04"+"0"*128,
                                     release_key_sha256=a.sha(bytes.fromhex("04"+"0"*128)))),
                      json.dumps(self.fields)[:-1]+', "owner_sha256":"'+OWNER+'"}'):
            self.p.write_text(body,encoding="utf8")
            with self.assertRaises(a.Refused):
                a.load_profile(self.p,a.sha(self.p.read_bytes()),self.fp)
    def fixture_package(self):
        v=self.d/"offline-fixture.vpk"
        s=self.d/"stage-confirmed.json"
        with zipfile.ZipFile(ROOT/"build/testapp.vpk") as z:
            sfo=z.read("sce_sys/param.sfo").replace(b"INAP00020",b"INAP00018").replace(b"01.01\0",TARGET.encode()+b"\0")
        with zipfile.ZipFile(v,"w") as z:
            z.writestr("sce_sys/param.sfo",sfo)
            z.writestr("eboot.bin",core_fixture((TX_BUILD.encode()+b"\0",)))
            z.writestr("workbench_payload.suprx",b"offline synthetic fixture")
        digest=hashlib.sha256(v.read_bytes()).hexdigest()
        pkg=r1ctl.local_package(v,digest,TX_BUILD)
        st=dict(result="STAGED_NOT_APPLIED",idle_source_run=RUN,source=dict(version=SOURCE,build=SOURCE+"-live-r1auto",
                run=RUN,host_sha256=HOST,transport_sha256="2"*64,channel="one interactive PTY"),
                package=pkg,pending=pkg["receipt"])
        s.write_text(json.dumps(st),encoding="utf-8")
        return v,s,digest,st
    def test_reconstruct_real_native_receipt_and_reject_archive_or_stage_mismatch(self):
        v,s,digest,st=self.fixture_package()
        scope,message=a.package_scope(self.trust,s,v,digest)
        self.assertEqual(scope["wbq2"],st["pending"])
        self.assertNotEqual(scope["manifest_sha256"],digest)
        self.assertEqual(scope["stage_record_sha256"],a.sha(s.read_bytes()))
        self.assertEqual(scope["message_sha256"],a.sha(message))
        self.assertTrue(a.verify_token(a.sign_token(self.trust,scope,message,self.key),self.trust,scope,message))
        with self.assertRaisesRegex(a.Refused,"archive"):
            a.package_scope(self.trust,s,v,"e"*64)
        for update in (dict(idle_source_run=RUN[::-1]),dict(pending=f"WBQ2 {TARGET} {digest} 31415"),
                       dict(source=dict(st["source"],host_sha256="e"*64))):
            with self.subTest(update=update),self.assertRaises(ValueError):
                s.write_text(json.dumps(dict(st,**update)),encoding="utf8")
                a.package_scope(self.trust,s,v,digest)
    def test_real_cli_sign_and_verify_offline_no_key_outputs_or_overwrite(self):
        v,s,digest,_=self.fixture_package()
        base=["--profile",str(self.p),"--profile-sha256",a.sha(self.p.read_bytes()),"--fingerprint",self.fp,
              "--stage",str(s),"--vpk",str(v),"--sha256", digest]
        out=self.d/"token.json"; key=self.d/"fixture-protected.path"
        calls=[]
        mod=ModuleType("standing_key_dpapi")
        def load(path):
            calls.append(path)
            return self.key
        mod.load=load
        with patch.dict(sys.modules,{"standing_key_dpapi":mod}),contextlib.redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(a.main(["sign",*base,"--key",str(key),"--output",str(out)]),0)
            self.assertEqual(a.main(["verify",*base,"--token",str(out)]),0)
            self.assertEqual(a.main(["sign",*base,"--key",str(key),"--output",str(out)]),3)
        rows=[json.loads(row) for row in capture.getvalue().splitlines()]
        self.assertEqual([x["status"] for x in rows],["SIGNED_OFFLINE_NOT_SUBMITTED","SIGNED_SCOPE_VERIFIED_NOT_SUBMITTED","REFUSED"])
        self.assertTrue(all(x["sent"] is False for x in rows))
        self.assertEqual(calls,[key])
        self.assertFalse(key.exists())
        self.assertNotIn("r1-signed",capture.getvalue())
        self.assertEqual(set(json.loads(out.read_bytes())),{"schema","scope","command","sent"})
    def test_path_policy_and_bounded_exclusive_output(self):
        leaf=self.d/"readonly.json"
        a.write_public(leaf,{"first":True})
        with self.assertRaises(FileExistsError):
            a.write_public(leaf,{"second":True})
        self.assertEqual(json.loads(leaf.read_bytes()),{"first":True})
        with self.assertRaisesRegex(ValueError,"parent traversal"):
            a.read_small(self.d/".."/"hidden",256)
    def test_key_not_read_when_prior_reconstruction_fails(self):
        v,s,digest,_=self.fixture_package()
        base=["--profile",str(self.p),"--profile-sha256",a.sha(self.p.read_bytes()),"--fingerprint",self.fp,
              "--stage",str(s),"--vpk",str(v),"--sha256", "e"*64]
        out=self.d/"unauthorized.json"
        mod=ModuleType("standing_key_dpapi")
        mod.load=lambda _: self.fail("key should not be read")
        with patch.dict(sys.modules,{"standing_key_dpapi":mod}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(a.main(["sign",*base,"--key",str(self.d/"fixture"),"--output",str(out)]),3)
        self.assertFalse(out.exists())


if __name__=="__main__":
    with patch.object(socket,"create_connection",side_effect=AssertionError("offline test: sockets forbidden")):
        unittest.main(verbosity=2)
