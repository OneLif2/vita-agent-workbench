"""Loopback reference endpoint for the WAKE-only SSH subsystem; not a Vita daemon.

No CLI, bind, discovery, persistence, arbitrary title, shell, exec, or
forwarding. Integration supplies a loopback socket and independent host key.
The real Vita adapter will need a device-local approval lease and platform
observer; never substitute a permissive readiness/launch callback there.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import re
import threading
import time

SUBSYSTEM='wb-wake-v1'
TITLE=b'INAP00018'
KEY_ALGO='ecdsa-sha2-nistp256'
RUN=re.compile(r'[0-9A-F]{16}')
HEX=re.compile(r'[a-f0-9]{64}')
REQUEST=re.compile(rb'(READY|OPEN) ([a-f0-9]{32})\n')
LEASE_TTL=60.0

def fp(key):
    return hashlib.sha256(key.asbytes()).hexdigest()

@dataclass(frozen=True)
class PlatformState:
    wake_worker_active: bool
    owner_enabled: bool
    safe_to_launch: bool
    workbench_running: bool | None

class Receiver:
    """Memory-only challenge. A physical user/OS policy, never SSH, grants a lease."""
    def __init__(self, run, sample, launch_fixed, now=time.monotonic):
        if not RUN.fullmatch(run):
            raise ValueError('expected independent receiver run')
        self.run=run.encode('ascii');self.sample=sample;self.launch_fixed=launch_fixed;self.now=now
        self._scope=threading.Lock()
        self._enabled=None;self._challenge=None;self._spent=True

    def enable_local(self):
        with self._scope:
            self._enabled=self.now();self._challenge=None;self._spent=False

    def revoke_local(self):
        with self._scope:
            self._enabled=None;self._challenge=None;self._spent=True

    def handle(self, data):
        m=REQUEST.fullmatch(data) if len(data)<=39 else None
        if not m:return 125,b'DENIED\n'
        with self._scope:
            t=self.now()
            if self._enabled is None or not 0<=t-self._enabled<LEASE_TTL or self._spent:
                return 126,b'NEEDS_OWNER\n'
            kind,c=m.groups()
            try: s=self.sample()
            except Exception: return 125,b'DENIED\n'
            if (not isinstance(s,PlatformState) or s.wake_worker_active is not True or
                s.owner_enabled is not True or type(s.workbench_running) is not bool):
                return 125,b'DENIED\n'
            if kind==b'READY':
                if self._challenge is not None:return 125,b'DENIED\n'
                self._challenge=c
                return 0,b'READY '+c+b' '+self.run+b' '+TITLE+b'\n'
            if self._challenge is None or not hmac.compare_digest(c,self._challenge):
                return 125,b'DENIED\n'
            if s.workbench_running:return 125,b'ALREADY_RUNNING\n'
            if s.safe_to_launch is not True:return 125,b'DENIED\n'
            self._spent=True
            # A lost acknowledgement, exception or platform failure never replays.
            try:
                if self.launch_fixed() is True:return 0,b'DISPATCHED_UNVERIFIED '+c+b' '+self.run+b' '+TITLE+b'\n'
            except Exception:pass
            return 1,b'PLATFORM_ERROR\n'

def serve_loopback_once(sock, host_key, owner_hash, receiver):
    """Own one connected loopback socket with one SSH session/subsystem only."""
    import paramiko
    def local(addr):return ipaddress.ip_address(addr[0]).is_loopback
    if not (local(sock.getpeername()) and local(sock.getsockname())):raise ValueError('reference only accepts loopback')
    if not HEX.fullmatch(owner_hash) or host_key.get_name()!=KEY_ALGO or hmac.compare_digest(fp(host_key),owner_hash):
        raise ValueError('independent SSH identities required')
    finished=threading.Event()
    class Gate(paramiko.ServerInterface):
        def __init__(self):self.used=False;self.subsystem=False
        def get_allowed_auths(self, username):return 'publickey'
        def check_auth_publickey(self,username,key):
            return (paramiko.AUTH_SUCCESSFUL if username=='pi' and key.get_name()==KEY_ALGO
                    and hmac.compare_digest(fp(key),owner_hash) else paramiko.AUTH_FAILED)
        def check_channel_request(self,kind,chanid):
            if kind!='session' or self.used:return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            self.used=True
            return paramiko.OPEN_SUCCEEDED
        def check_channel_subsystem_request(self,channel,name):
            if name!=SUBSYSTEM or self.subsystem:return False
            self.subsystem=True
            return super().check_channel_subsystem_request(channel,name)
    class Handler(paramiko.SubsystemHandler):
        def start_subsystem(self,name,transport,channel):
            try:
                buf=bytearray();stop=time.monotonic()+3
                while time.monotonic()<stop:
                    channel.settimeout(max(.05,stop-time.monotonic()))
                    c=channel.recv(64)
                    if not c:
                        rc,out=receiver.handle(bytes(buf));break
                    buf.extend(c)
                    if len(buf)>39:
                        rc,out=125,b'DENIED\n';break
                else: return
                channel.sendall(out);channel.send_exit_status(rc);channel.shutdown_write()
            finally:finished.set()
        def finish_subsystem(self):
            super().finish_subsystem()
    with paramiko.Transport(sock) as tr:
        tr.banner_timeout=3;tr.auth_timeout=3
        tr.get_security_options().key_types=(KEY_ALGO,)
        tr.add_server_key(host_key);tr.set_subsystem_handler(SUBSYSTEM,Handler)
        tr.start_server(server=Gate())
        channel=tr.accept(3)
        if channel is not None:finished.wait(4)
