#!/usr/bin/env python3
"""Read-only Workbench 02.06 foreground health check constants and legacy CLI.
Requires an already armed Workbench. No shell, launch, autoarm, installation, or reconnect.
A successful report is about Workbench only, NOT a TestApp job or a lock-screen test.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

COMMANDS = ("ver", "status", "ver")
POWER_COMMANDS = ("ver", "status", "ext sys", "ver")
PAYLOAD = "01.22-p2.1"
VERSION = "02.06"
BUILD = "02.06-live-safequery"
PORT = 2222
MAX_REPLY = 2048
TOTAL_TIMEOUT = 25
VR = re.compile(r"wb version=(\S+) build=(\S+) abi=(\d+) proto=(\S+) run=([0-9a-fA-F]{16}) payload=(\S+) uptime_ms=(\d+)")
ST = re.compile(r"run=([0-9a-fA-F]{16}) uptime_ms=(\d+) ssh=(\S+) cmds=(\d+) payload=(\S+) core=(\S+) last_install=(?:none|\d+ms-ago) peer=\S+:\d+")

class Problem(Exception):
    """A fixed, local reason code; never dump server output, keys, or user paths."""

def ensure(ok, reason):
    if not ok:
        raise Problem(reason)

def screen_pin(value):
    p = "".join(value.split()).lower()
    ensure(bool(re.fullmatch(r"[0-9a-f]{64}", p)), "invalid_screen_sha256")
    return p

def read_reply(tr, command, deadline):
    ensure(command in POWER_COMMANDS, "command_not_supported")
    ensure(tr.is_active() and tr.is_authenticated(), "original_transport_lost")
    ch = tr.open_session(timeout=min(5, max(0.01, deadline-time.monotonic())))
    try:
        ch.settimeout(5)
        ch.exec_command(command)
        out = bytearray()
        while True:
            ensure(time.monotonic() < deadline, "reply_deadline")
            if ch.recv_ready():
                out.extend(ch.recv(1024))
            if ch.recv_stderr_ready():
                raise Problem("remote_stderr")
            ensure(len(out) <= MAX_REPLY, "reply_too_large")
            if ch.closed and not ch.recv_ready():
                break
            time.sleep(0.005)
        ensure(ch.exit_status_ready() and ch.recv_exit_status() == 0, "nonzero_or_missing_exit")
        try:
            text = bytes(out).decode("ascii")
        except UnicodeDecodeError:
            raise Problem("non_ascii_reply") from None
        lines = text.splitlines()
        if command == "ext sys":
            ensure(len(lines)==7, "unexpected_power_format")
            return "\n".join(lines)
        ensure(len(lines) == 1 and lines[0], "not_one_result_line")
        return lines[0]
    finally:
        ch.close()

def checked_ver(line):
    m = VR.fullmatch(line)
    ensure(m is not None, "unexpected_ver_format")
    version, build, abi, proto, run, payload, uptime = m.groups()
    ensure((version,build,abi,proto)==(VERSION,BUILD,"3","wb10"), "unexpected_core_identity")
    ensure(payload in ("none",PAYLOAD), "unexpected_payload")
    return run.upper(), payload, int(uptime)

def compare_status(line, first):
    m = ST.fullmatch(line)
    ensure(m is not None, "unexpected_status_format")
    run, uptime, connected, _, payload, core = m.groups()
    ensure(connected == "connected", "status_does_not_show_connected")
    ensure((run.upper(),payload,core)==(first[0],first[1],VERSION), "run_payload_or_core_changed")
    return int(uptime)

def compare(rows):
    first=checked_ver(rows[0]); middle_uptime=compare_status(rows[1],first); last=checked_ver(rows[-1])
    ensure(last[:2]==first[:2],"run_payload_or_core_changed")
    times=[first[2],middle_uptime,last[2]]
    ensure(times[0] <= times[1] <= times[2] and times[2] > times[0], "uptime_not_progressing")
    return dict(core=VERSION,build=BUILD,run=first[0],payload=first[1],uptime_ms=times)

def checked_power(text, times):
    pattern=(r"payload sys version=01\.22-p2\.1\npayload abi=3\npayload uptime_ms=(\d+)"
             r"\npayload battery=(\d+)\npayload temp_c=(unavailable|\d+)\npayload charging=([01])\npayload online=([01])")
    m=re.fullmatch(pattern,text); ensure(m is not None,"unexpected_power_format")
    up,battery,temp,charging,online=m.groups(); ensure(times[1]<=int(up)<=times[-1],"power_uptime_not_in_run")
    ensure(int(battery)<=100 and temp!="unavailable" and int(temp)<=100,"power_reading_unavailable_or_out_of_range")
    return dict(battery_percent=int(battery),temperature_c=int(temp),charging=bool(int(charging)),online=bool(int(online)))

def measure(host, expected_pin, keyfile, *, case="core", port=PORT, open_socket=socket.create_connection,
            transport_factory=None, owner_key_loader=None):
    """Single outgoing connection, three or four fixed read-only EXEC requests, no retry."""
    ensure(case in ("core","power"),"unsupported_case")
    commands=COMMANDS if case=="core" else POWER_COMMANDS
    try:
        addr = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise Problem("expected_lan_ipv4_literal") from None
    ensure((addr.is_private or addr.is_loopback) and not addr.is_multicast and not addr.is_unspecified
           and not addr.is_reserved, "expected_lan_ipv4_literal")
    pin = screen_pin(expected_pin)             # Validate input before opening a socket.
    if transport_factory is None or owner_key_loader is None:
        try:
            import paramiko
        except ImportError:
            raise Problem("paramiko_not_installed") from None
        transport_factory = paramiko.Transport
        owner_key_loader = paramiko.ECDSAKey.from_private_key_file
    with open_socket((str(addr),port),timeout=5) as sock:
        tr = transport_factory(sock)
        timer = threading.Timer(TOTAL_TIMEOUT,tr.close)  # Also bounds SSH exec-request acknowledgement.
        timer.daemon = True
        deadline = time.monotonic() + TOTAL_TIMEOUT
        timer.start()
        try:
            tr.auth_timeout = 6
            tr.banner_timeout = 6
            tr.start_client(timeout=7)
            hostkey = tr.get_remote_server_key()
            ensure(hostkey.get_name()=="ecdsa-sha2-nistp256" and
                   hmac.compare_digest(hashlib.sha256(hostkey.asbytes()).hexdigest(),pin),
                   "screen_host_key_mismatch")
            # Do not load the private owner key, or offer authentication, before the above check.
            tr.auth_publickey("pi", owner_key_loader(str(keyfile)))
            ensure(tr.is_authenticated() and tr.is_active(), "owner_auth_failed")
            sid = bytes(tr.session_id)
            ensure(bool(sid), "missing_transport_identity")
            rows = []
            for cmd in commands:
                rows.append(read_reply(tr, cmd, deadline))
                # Stop immediately on an unexpected initial identity, before even querying status.
                if len(rows)==1:
                    first=checked_ver(rows[0])
                    if case=="power":ensure(first[1]==PAYLOAD,"power_requires_already_active_payload")
                if len(rows)==2: compare_status(rows[1],first)
            result = compare(rows)
            if case=="power":result["power"]=checked_power(rows[2],result["uptime_ms"])
            ensure(tr.is_active() and tr.is_authenticated() and hmac.compare_digest(bytes(tr.session_id),sid),
                   "original_transport_lost")
            ensure(time.monotonic() < deadline, "health_deadline")
            return dict(result="PASS",scope="already_armed_workbench_not_testapp",case=case,**result,
                        transport_sha256=hashlib.sha256(sid).hexdigest(),commands=list(commands))
        finally:
            timer.cancel()
            tr.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case",choices=("core","power"),default="core",help="power only reads an already active 01.22-p2.1 payload; otherwise returns INCONCLUSIVE")
    parser.add_argument("--host",required=True,help="already-armed Vita's LAN IPv4 address")
    parser.add_argument("--fingerprint",required=True,help="current screen SSH HOST KEY SHA256 HEX, quote if spaced; never use old boot's pin")
    parser.add_argument("--key",type=Path,default=Path.home()/".ssh/id_ecdsa_wb",help="existing owner ECDSA identity (not copied)")
    args=parser.parse_args()
    try:
        report=measure(args.host,args.fingerprint,args.key,case=args.case)
    except (Exception,KeyboardInterrupt) as exc:
        # No automatic reconnection, install, write, or title launch on error.
        report=dict(result="INCONCLUSIVE",scope="already_armed_workbench_not_testapp",case=args.case,
                    reason=str(exc) if isinstance(exc,Problem) else type(exc).__name__)
    report["utc"]=datetime.now(timezone.utc).isoformat()
    print(json.dumps(report,ensure_ascii=True))
    return 0 if report["result"]=="PASS" else 2

if __name__=="__main__":
    raise SystemExit(main())

