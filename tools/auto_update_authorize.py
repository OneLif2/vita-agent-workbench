"""Offline, explicitly scoped Workbench release signer. No SSH or install command is sent."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import review_digest
import wb_tree

PROFILE_SCHEMA = "wb.r1.auto.profile.v1"
TOKEN_SCHEMA = "wb.r1.auto.authorization.v1"
DOMAIN = "WB-R1-AUTO-v1"
TITLE = "INAP00018"
HEX = re.compile(r"[0-9a-f]{64}")
RUN = re.compile(r"[0-9A-F]{16}")
VERSION = re.compile(r"[0-9]{2}\.[0-9]{2}")
PUB = re.compile(r"04[0-9a-f]{128}")
COMMAND = re.compile(r"r1-signed ([0-9a-f]{64}) ([0-9a-f]{64})")
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
MAX_STAGE = 32 * 1024 * 1024
MAX_VPK = 4 * 1024 * 1024


class Refused(ValueError):
    pass


def require(ok, description):
    if not ok:
        raise Refused(description)


def text(pattern, value, reason, *, nonzero=False):
    require(isinstance(value, str) and pattern.fullmatch(value), reason)
    if nonzero:
        require(int(value, 16) != 0, reason)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def eq(a,b):
    return isinstance(a,str) and isinstance(b,str) and a.isascii() and b.isascii() and hmac.compare_digest(a,b)


def read_small(path, cap):
    with wb_tree.checked_open(path) as f:
        raw=f.read(cap+1)
    require(0<len(raw)<=cap, "local input size was not permitted")
    return raw


def json_unique(raw):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result, "duplicate JSON parameter")
            result[k]=v
        return result
    def reject(_):
        raise Refused("nonfinite JSON parameter")
    return json.loads(raw,object_pairs_hook=unique,parse_constant=reject)


def public_sec1(key):
    return key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)


def ssh_owner_fingerprint(sec1):
    fields=(b"ecdsa-sha2-nistp256",b"nistp256",sec1)
    return sha(b"".join(struct.pack(">I",len(x))+x for x in fields))


@dataclass(frozen=True)
class Trust:
    profile_sha256: str
    host_sha256: str
    owner_sha256: str
    release_key_sha256: str
    sec1: bytes

    def key(self):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),self.sec1)


def load_profile(path, profile_sha, fingerprint):
    want=text(HEX,profile_sha,"expected independently recorded profile SHA-256",nonzero=True)
    pin=text(HEX,fingerprint,"expected independently confirmed release-key fingerprint",nonzero=True)
    raw=read_small(path,4096)
    require(eq(sha(raw),want),"local standing profile SHA-256 differs")
    p=json_unique(raw)
    require(isinstance(p,dict) and set(p)=={"schema","host_sha256","owner_sha256","release_key_sha256","release_key_sec1"}
            and p["schema"]==PROFILE_SCHEMA,"unexpected standing profile")
    host=text(HEX,p["host_sha256"],"invalid Vita host pin",nonzero=True)
    owner=text(HEX,p["owner_sha256"],"invalid owner pin",nonzero=True)
    keypin=text(HEX,p["release_key_sha256"],"invalid release key pin",nonzero=True)
    sec1=bytes.fromhex(text(PUB,p["release_key_sec1"],"invalid release P-256 public point"))
    require(eq(keypin,pin) and eq(sha(sec1),pin), "release public fingerprint differs")
    require(len({host,owner,keypin})==3 and not eq(ssh_owner_fingerprint(sec1),owner) and not eq(ssh_owner_fingerprint(sec1),host),
            "release signing key must differ from the paired SSH and host keys")
    try: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),sec1)
    except ValueError as ex: raise Refused("invalid P-256 public point") from ex
    return Trust(want,host,owner,keypin,sec1)


def canonical(target,manifest,stage_bytes,host,owner,source,run):
    text(VERSION,target,"invalid target version")
    text(VERSION,source,"invalid source version")
    require(source<target,"update must be strictly newer than the running version")
    text(HEX,manifest,"invalid Stage digest",nonzero=True)
    require(type(stage_bytes) is int and 0<stage_bytes<=MAX_STAGE,"invalid Stage byte total")
    text(HEX,host,"invalid Vita host pin",nonzero=True)
    text(HEX,owner,"invalid owner pin",nonzero=True)
    require(not eq(host,owner),"host and owner identities cannot match")
    text(RUN,run,"invalid source run",nonzero=True)
    return f"{DOMAIN}\n{TITLE} {target} {manifest} {stage_bytes}\nHOST {host}\nOWNER {owner}\nSOURCE {source} {run}\n".encode("ascii")


def package_scope(trust, stage, vpk, archive_sha, local_expected=review_digest.load_expected):
    """Independently reconstruct WBQ2 using snapshots of the stage record and approved archive."""
    approved=text(HEX,archive_sha,"expected separately approved archive SHA-256",nonzero=True)
    stage_bytes=read_small(stage,65536)
    archive=read_small(vpk,MAX_VPK)
    require(eq(sha(archive),approved),"VPK SHA-256 differs from the approved archive")
    with tempfile.TemporaryDirectory(prefix="wb-auto-authorize-") as tmp:
        base=Path(tmp)
        a=base/"release.vpk"; a.write_bytes(archive)
        s=base/"stage.json"; s.write_bytes(stage_bytes)
        try:e=local_expected(a,approved,s)
        except review_digest.ReviewError as ex:raise Refused("stage does not match the independently reconstructed package") from ex
    require(e.get("title")==TITLE and eq(e.get("vpk_sha256"),approved)
            and eq(e.get("host_sha256"),trust.host_sha256), "unbound title/package/host in stage witness")
    m=canonical(e["version"],e["manifest"],e["bytes"],trust.host_sha256,trust.owner_sha256,e["source_version"],e["source_run"])
    receipt=f"WBQ2 {e['version']} {e['manifest']} {e['bytes']}"
    require(eq(e.get("receipt"),receipt),"noncanonical WBQ2 receipt")
    scope=dict(title=TITLE,target=e["version"],manifest_sha256=e["manifest"],stage_bytes=e["bytes"],
               source_version=e["source_version"],source_run=e["source_run"],host_sha256=trust.host_sha256,
               owner_sha256=trust.owner_sha256,release_key_sha256=trust.release_key_sha256,profile_sha256=trust.profile_sha256,
               stage_record_sha256=sha(stage_bytes),approved_vpk_sha256=approved,wbq2=receipt,message_sha256=sha(m))
    return scope,m


def verify_token(token,trust,scope,message):
    require(isinstance(token,dict) and set(token)=={"schema","scope","command","sent"}
            and token["schema"]==TOKEN_SCHEMA and token["sent"] is False and token["scope"]==scope,
            "authorization record does not bind exact local scope")
    cmd=text(COMMAND,token["command"],"invalid fixed signature encoding")
    match=COMMAND.fullmatch(cmd)
    r,s=(int(x,16) for x in match.groups())
    require(0<r<P256_N and 0<s<=P256_N//2,"noncanonical P-256 signature")
    try:trust.key().verify(utils.encode_dss_signature(r,s),message,ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as ex:raise Refused("signature does not authorize this exact stage") from ex
    return True


def sign_token(trust,scope,message,key):
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1),
            "protected signing key is not P-256")
    require(hmac.compare_digest(public_sec1(key.public_key()),trust.sec1),"protected signing key does not match the enrolled release key")
    r,s=utils.decode_dss_signature(key.sign(message,ec.ECDSA(hashes.SHA256())))
    canonical_s=min(s,P256_N-s)
    result=dict(schema=TOKEN_SCHEMA,scope=scope,command=f"r1-signed {r:064x} {canonical_s:064x}",sent=False)
    verify_token(result,trust,scope,message)
    return result


def write_public(path, value):
    out=wb_tree.source_path(path)
    with out.open("x",encoding="utf-8",newline="\n") as f:
        json.dump(value,f,indent=2,ensure_ascii=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    modes=p.add_subparsers(dest="mode",required=True)
    for mode in ("sign","verify"):
        q=modes.add_parser(mode,allow_abbrev=False)
        for name in ("profile","stage","vpk"):
            q.add_argument("--"+name,required=True,type=Path)
        for name in ("profile-sha256","fingerprint","sha256"):
            q.add_argument("--"+name,required=True)
        if mode=="sign":
            q.add_argument("--key",required=True,type=Path,help="local Windows user-protected DPAPI key")
            q.add_argument("--output",required=True,type=Path,help="new public record; never overwritten")
        else:q.add_argument("--token",required=True,type=Path)
    a=p.parse_args(argv)
    try:
        trust=load_profile(a.profile,a.profile_sha256,a.fingerprint)
        scope,message=package_scope(trust,a.stage,a.vpk,a.sha256)
        if a.mode=="sign":
            out=wb_tree.source_path(a.output)
            require(not os.path.lexists(out),"authorization output exists")
            from standing_key_dpapi import load
            token=sign_token(trust,scope,message,load(wb_tree.source_path(a.key)))
            write_public(out,token)
            report=dict(status="SIGNED_OFFLINE_NOT_SUBMITTED",token=str(out),target=scope["target"],
                        source_run=scope["source_run"],sent=False)
        else:
            verify_token(json_unique(read_small(a.token,8192)),trust,scope,message)
            report=dict(status="SIGNED_SCOPE_VERIFIED_NOT_SUBMITTED",target=scope["target"],
                        source_run=scope["source_run"],sent=False)
        print(json.dumps(report,ensure_ascii=True))
        return 0
    except Exception as ex:
        # Do not stringify lower-level failures which might contain key loader
        # contents, process paths, or attacker-selected metadata.
        out=dict(status="REFUSED",reason=str(ex) if type(ex) is Refused else type(ex).__name__,sent=False)
        print(json.dumps(out,ensure_ascii=True))
        return 3


if __name__=="__main__":
    raise SystemExit(main())
