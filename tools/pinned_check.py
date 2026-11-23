#!/usr/bin/env python3
"""Workbench pairing and read-only 5090 health check. No remote commands during pairing."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import tempfile

import check_in_place as health

ALGO = "ecdsa-sha2-nistp256"
DEFAULT_HOST = "192.0.2.10"


class PairError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise PairError(message)


def endpoint(host, port):
    addr = ipaddress.IPv4Address(host)
    require(any(addr in ipaddress.IPv4Network(n) for n in
                ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8")),
            "expected LAN IPv4 address")
    port = int(port)
    require(1 <= port <= 65535, "invalid port")
    return str(addr), port


def label(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def pin_path(host, port):
    host, port = endpoint(host, port)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        require(base and Path(base).is_absolute(), "LOCALAPPDATA unavailable")
        base = Path(base)
    else:
        base = Path.home() / ".local" / "state"
    return base / "VitaWorkbench" / "trust" / f"{host}_{port}.known_hosts"


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def validate_blob(blob):
    """Accept one OpenSSH P-256 public key blob and no suffix."""
    parts = []
    pos = 0
    for _ in range(3):
        require(pos + 4 <= len(blob) <= 512, "malformed public key")
        n = struct.unpack_from(">I", blob, pos)[0]
        pos += 4
        require(n <= len(blob)-pos, "malformed public key")
        parts.append(blob[pos:pos+n])
        pos += n
    require(pos == len(blob) and parts[0] == ALGO.encode() and parts[1] == b"nistp256"
            and len(parts[2]) == 65 and parts[2][0] == 4, "unexpected SSH public key")
    return blob


def saved_pin(path, host, port):
    require(not path.is_symlink(), "pin file must not be a symlink")
    if not path.exists():
        raise PairError("not paired; enroll using the Vita screen fingerprint first")
    with path.open("rb") as inp:
        line = inp.read(1025)
    require(len(line) <= 1024, "invalid pin store")
    fields = line.decode("ascii").split(" ")
    require(len(fields) == 3 and fields[:2] == [label(host, port), ALGO], "invalid pin endpoint/key type")
    try:
        data = base64.b64decode(fields[2].rstrip("\n"), validate=True)
    except binascii.Error:
        raise PairError("malformed pinned host key") from None
    canonical = f"{label(host,port)} {ALGO} ".encode()+base64.b64encode(validate_blob(data))+b"\n"
    require(line == canonical, "non-canonical pin store")
    return digest(data)


def observe(host, port):
    """Unauthenticated key exchange; never open, load or offer an owner key here."""
    import paramiko
    with socket.create_connection((host,port), timeout=5) as sock:
        with paramiko.Transport(sock) as tr:
            tr.banner_timeout = 5
            tr.start_client(timeout=7)
            key = tr.get_remote_server_key()
            require(key.get_name() == ALGO, "unexpected host key type")
            return validate_blob(key.asbytes())


def canonical_saved(path, host, port):
    """The Store Python view of LOCALAPPDATA may differ from native ssh.exe's.
    Reopen the resolved physical file; it must have the same validated endpoint and key.
    """
    expected = saved_pin(path,host,port)
    physical = path.resolve(strict=True)
    actual = saved_pin(physical,host,port)
    require(hmac.compare_digest(expected,actual), "resolved pin differs from registered pin")
    return physical,actual


def pair(path, host, port, current_screen, *, old=None, observer=None):
    host,port = endpoint(host,port)
    screen = health.screen_pin(current_screen)
    if old is not None:
        old = health.screen_pin(old)
        require(old != screen, "old and new fingerprint are identical")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = path.with_suffix(".lock")
    try:
        lock_handle = lock.open("xb")
    except FileExistsError:
        raise PairError("pairing in progress or stale lock; inspect before recovery") from None
    tmp = None
    try:
        lock_handle.close()
        if old is None:
            require(not path.exists() and not path.is_symlink(), "already paired; never overwrite on enroll")
        else:
            require(hmac.compare_digest(saved_pin(path,host,port),old), "old fingerprint mismatch")
        blob = validate_blob((observer or observe)(host,port))
        require(hmac.compare_digest(digest(blob),screen), "current screen fingerprint mismatch; pin unchanged")
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".wb-pair-", delete=False) as f:
            tmp = Path(f.name)
            f.write(f"{label(host,port)} {ALGO} ".encode()+base64.b64encode(blob)+b"\n")
            f.flush()
            os.fsync(f.fileno())
        require(hmac.compare_digest(saved_pin(tmp,host,port), screen), "cannot verify staged pin")
        os.replace(tmp,path)
        return saved_pin(path,host,port)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)


def openssh_argv(host, port, owner_key, user):
    """One common fail-closed transport policy for wbctl reads, uploads and updates."""
    host,port = endpoint(host,port)
    require(user == "pi", "unsupported Workbench account")
    path,_ = canonical_saved(pin_path(host,port),host,port)
    cfg_path = path.as_posix()
    require(not any(c in cfg_path for c in '\"\r\n%$'), "unsupported trust-store path")
    return ["ssh","-F","none","-T","-p",str(port),"-i",str(owner_key),
            "-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","ConnectTimeout=8",
            "-o","PreferredAuthentications=publickey","-o","ForwardAgent=no","-o","IdentityAgent=none",
            "-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=none",
            "-o",f'UserKnownHostsFile="{cfg_path}"',"-o","UpdateHostKeys=no",
            "-o","VerifyHostKeyDNS=no","-o",f"HostKeyAlgorithms={ALGO}",
            "-o","ControlMaster=no","-o","ControlPath=none",f"{user}@{host}"]


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host",default=os.environ.get("WB_HOST",DEFAULT_HOST))
    ap.add_argument("--port",type=int,default=os.environ.get("WB_PORT","2222"))
    sub=ap.add_subparsers(dest="action",required=True)
    for action in ("enroll","re-pair"):
        p=sub.add_parser(action)
        p.add_argument("--screen-fingerprint",required=True,help="obtained independently from the CURRENT Vita screen")
        if action=="re-pair":
            p.add_argument("--old-fingerprint",required=True,help="previously trusted digest")
    sub.add_parser("show")
    p=sub.add_parser("check")
    p.add_argument("--case",choices=("core","power"),default="core")
    p.add_argument("--key",type=Path,default=os.environ.get("WB_KEY",Path.home()/".ssh"/"id_ecdsa_wb"))
    args=ap.parse_args(argv)
    try:
        host,port=endpoint(args.host,args.port)
        path=pin_path(host,port)
        if args.action=="check":
            _,fp=canonical_saved(path,host,port)
            report=health.measure(host,fp,args.key,case=args.case,port=port)
        elif args.action=="show":
            physical,fp=canonical_saved(path,host,port)
            report={"result":"PINNED","fingerprint":fp,"path":str(physical)}
        else:
            fp=pair(path,host,port,args.screen_fingerprint,old=getattr(args,"old_fingerprint",None))
            physical,actual=canonical_saved(path,host,port)
            require(hmac.compare_digest(fp,actual),"resolved pin changed after pairing")
            report={"result":"PAIRED","fingerprint":fp,"path":str(physical)}
    except Exception as exc:
        reason=str(exc) if isinstance(exc,(PairError,health.Problem)) else type(exc).__name__
        print(json.dumps({"result":"INCONCLUSIVE","reason":reason}))
        return 2
    print(json.dumps(report)); return 0


if __name__=="__main__":
    raise SystemExit(main())
