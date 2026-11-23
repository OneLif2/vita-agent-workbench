"""Readiness only: pinned current WB PTYs bracket a fixed receiver subsystem challenge."""
from __future__ import annotations

import contextlib
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time

import r1ctl
import stage_review
import wbterm as wb

ROOT = Path(__file__).resolve().parents[1]
SUBSYSTEM = 'wb-wake-v1'
RECEIVER = (wb.HOST, 2224)
PROFILE_NAME = 'wb-wake-subsystem.local.json'  # Never shared with the historical exec workflow.
P256 = 'ecdsa-sha2-nistp256'
PIN = re.compile(r'[0-9a-f]{64}')
RUN = re.compile(r'[0-9A-F]{16}')
VERSION = re.compile(r'[0-9]{2}\.[0-9]{2}')
CHALLENGE = re.compile(r'[0-9a-f]{32}')


class Gate(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Gate(reason)


def hex_nonzero(value, pattern):
    return isinstance(value, str) and bool(pattern.fullmatch(value)) and int(value, 16) != 0


def data_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(key):
    return data_hash(key.asbytes())


def distinct(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate enrollment field')
        result[key] = value
    return result


def enrollment(path, wb_pin):
    with wb.wb_tree.checked_open(path) as f:
        raw = f.read(2049)
    need(0 < len(raw) <= 2048, 'missing or oversized enrollment')
    obj = json.loads(raw, object_pairs_hook=distinct)
    names = {'schema', 'wb_sha256', 'receiver_sha256', 'owner_sha256'}
    need(isinstance(obj, dict) and set(obj) == names and obj['schema'] == 'wb.wake.local-enrollment.v1',
         'bad separate receiver enrollment')
    pins = [obj[k] for k in names if k != 'schema']
    need(all(hex_nonzero(x, PIN) for x in pins) and len(set(pins)) == 3, 'distinct valid enrollment fingerprints required')
    need(hmac.compare_digest(obj['wb_sha256'], wb_pin), 'enrollment WB pin changed')
    return obj, data_hash(raw)


def saved_pin():
    path, digest = wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST, wb.PORT), wb.HOST, wb.PORT)
    return digest, data_hash(path.read_bytes())


def key_loader(paramiko):
    path = Path(os.getenv('WB_KEY', str(Path.home()/'.ssh/id_ecdsa_wb')))
    return paramiko.ECDSAKey.from_private_key_file(str(path))


def original_pin(obj, trust, expected):
    need(trust() == expected and hmac.compare_digest(obj['wb_sha256'], expected[0]), 'saved WB pin changed')


def wb_identity(tty, pin):
    actual = tty.check()  # Fixed ver -> status -> ver on one interactive PTY.
    need(isinstance(actual, dict) and tty.host_pin == pin and actual.get('host_sha256') == pin
         and actual.get('transport_sha256') == tty.transport_id and hex_nonzero(tty.transport_id, PIN)
         and actual.get('channel') == 'one interactive PTY', 'not the original authenticated WB PTY')
    v = actual.get('version')
    need(isinstance(v, str) and bool(VERSION.fullmatch(v)) and actual['version'] == tty.version
         and isinstance(actual.get('build'), str) and bool(re.fullmatch(re.escape(v)+r'-[A-Za-z0-9._-]{1,40}', actual['build']))
         and hex_nonzero(actual.get('run'), RUN), 'WB process identity invalid')
    return actual


def no_active_r1(row, identity):
    st = r1ctl.parse_state(row)
    if st['run'] != identity['run']:
        return False
    if st['state'] == 'none':
        return all(st[k] == '-' for k in ('source_run', 'nonce', 'target', 'manifest'))
    return (st['state'] == 'returned' and st['source_run'] != st['run'] and hex_nonzero(st['source_run'], RUN)
            and hex_nonzero(st['nonce'], re.compile(r'[0-9A-F]{32}')) and hex_nonzero(st['manifest'], PIN)
            and st['target'] == identity['version'])


def watch_wb(paired, pin, trust, profile, rows=stage_review.reply):
    original_pin(profile, trust, pin)
    with paired() as tty:
        a = wb_identity(tty, pin[0])
        need(rows(tty, 'pending') == ['pending-core: no'], 'WB upgrade queue is not empty')
        need(no_active_r1(tty.one('r1-status'), a), 'WB upgrade authorization is active or uncertain')
        need(wb_identity(tty, pin[0]) == a, 'WB process or connection changed during observation')
        original_pin(profile, trust, pin)
    return a


def parse_ready(raw, challenge):
    need(isinstance(raw, bytes) and len(raw) <= 80 and isinstance(challenge, str)
         and bool(CHALLENGE.fullmatch(challenge)), 'bad bounded READY challenge or response')
    m = re.fullmatch(rb'READY ([0-9a-f]{32}) ([0-9A-F]{16}) INAP00018\n', raw)
    need(m and hmac.compare_digest(m[1], challenge.encode('ascii')) and int(m[2], 16) != 0,
         'receiver did not answer this challenge for Workbench')
    return m[2].decode('ascii')


def receiver_ready(profile, challenge, owner_loader=key_loader, open_socket=socket.create_connection, paramiko_module=None):
    """One authenticated fixed subsystem only. No exec, shell, apply or launch."""
    need(isinstance(challenge, str) and bool(CHALLENGE.fullmatch(challenge)), 'invalid challenge bytes')
    if paramiko_module is None:
        import paramiko as paramiko_module
    with open_socket(RECEIVER, timeout=4) as sock:
        def expire():
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        timer = threading.Timer(12, expire)
        timer.daemon = True
        timer.start()
        try:
            with paramiko_module.Transport(sock) as t:
                t.banner_timeout = t.auth_timeout = t.channel_timeout = 4
                t.get_security_options().key_types = (P256,)
                t.start_client(timeout=4)
                key = t.get_remote_server_key()
                need(key.get_name() == P256 and hmac.compare_digest(fingerprint(key), profile['receiver_sha256']),
                     'receiver pin mismatch; owner key not sent')
                owner = owner_loader(paramiko_module)
                need(owner.get_name() == P256 and hmac.compare_digest(fingerprint(owner), profile['owner_sha256']),
                     'configured owner public fingerprint differs from enrollment')
                t.auth_publickey(wb.USER, owner)
                need(t.is_authenticated() and t.is_active(), 'receiver did not authenticate paired owner')
                sid = data_hash(bytes(t.session_id))
                with t.open_session(timeout=4) as ch:
                    ch.settimeout(4)
                    ch.invoke_subsystem(SUBSYSTEM)
                    ch.sendall(('READY '+challenge+'\n').encode('ascii'))
                    ch.shutdown_write()
                    raw = bytearray()
                    while True:
                        need(not ch.recv_stderr_ready(), 'receiver returned unexpected stderr')
                        data = ch.recv(80)
                        if not data:
                            break
                        raw.extend(data)
                        need(len(raw) <= 80, 'oversized READY response')
                    end = time.monotonic()+4
                    while not ch.exit_status_ready() and time.monotonic() < end:
                        time.sleep(.008)
                    need(ch.exit_status_ready() and ch.recv_exit_status() == 0 and not ch.recv_stderr_ready(),
                         'missing clean receiver subsystem exit')
                    return dict(receiver_run=parse_ready(bytes(raw), challenge), challenge=challenge, target='INAP00018',
                                receiver_sha256=profile['receiver_sha256'], owner_sha256=profile['owner_sha256'],
                                transport_sha256=sid, subsystem=SUBSYSTEM)
        finally:
            timer.cancel()


def preflight(report, path, *, paired=wb.paired_terminal, trust=saved_pin, load=enrollment,
              receiver=receiver_ready, nonce=secrets.token_hex, rows=stage_review.reply):
    if not path.exists():
        return 'NO_RECEIVER_ENROLLMENT'
    pin = trust()
    need(len(pin) == 2 and all(hex_nonzero(x, PIN) for x in pin), 'invalid original WB pin')
    obj, digest = load(path, pin[0])
    before = watch_wb(paired, pin, trust, obj, rows)
    report['before'] = before
    challenge = nonce(16)
    need(hex_nonzero(challenge, CHALLENGE), 'invalid fresh READY nonce')
    proof = receiver(obj, challenge)
    need(isinstance(proof, dict) and proof.get('subsystem') == SUBSYSTEM and proof.get('target') == 'INAP00018'
         and proof.get('challenge') == challenge and proof.get('receiver_sha256') == obj['receiver_sha256']
         and proof.get('owner_sha256') == obj['owner_sha256'] and hex_nonzero(proof.get('receiver_run'), RUN)
         and hex_nonzero(proof.get('transport_sha256'), PIN) and proof['transport_sha256'] != before['transport_sha256'],
         'unbound receiver proof')
    report['receiver'] = proof
    after = watch_wb(paired, pin, trust, obj, rows)
    report['after'] = after
    need(all(after[k] == before[k] for k in ('version', 'build', 'run', 'host_sha256')) and
         len({after['transport_sha256'], before['transport_sha256'], proof['transport_sha256']}) == 3,
         'WB run, pin or corresponding fresh connection changed')
    need(load(path, pin[0]) == (obj, digest), 'local enrollment changed while measuring readiness')
    report['enrollment_sha256'] = digest
    return 'PREFLIGHT_READY_OWNER_CLOSE_ONLY'


def register(sub):
    p = sub.add_parser('wake-preflight', allow_abbrev=False, help='verify separate WB-only receiver while WB remains open (no close or launch)')
    p.add_argument('--json', action='store_true', default=argparse.SUPPRESS)


def open_status(endpoint, path=None, *, paired=wb.paired_terminal, trust=saved_pin):
    """Compatibility advisory, not a wake request. This version never sends OPEN."""
    result=dict(launch_sent=False,wake_sent=False,causal_pass=False)
    if endpoint != (wb.HOST, str(wb.PORT), wb.USER):
        return 3,dict(result,status='WAKE_UNAVAILABLE')
    path = path if path is not None else Path.home()/'.ssh'/PROFILE_NAME
    try:
        original = trust()
        need(len(original) == 2 and all(hex_nonzero(x, PIN) for x in original), 'invalid original WB pin')
        with paired() as tty:
            current = wb_identity(tty, original[0])
            need(trust() == original, 'saved WB pin changed')
        return 0,dict(result,status='ALREADY_RUNNING',run=current['run'])
    except ConnectionRefusedError:
        return 3,dict(result,status='WAKE_UNAVAILABLE' if path.is_file() else 'NO_ENROLLED_RECEIVER')
    except Exception:
        return 3,dict(result,status='WAKE_UNAVAILABLE')


def command(args, endpoint):
    report = dict(schema='wb.wake.preflight.v1', status='PREFLIGHT_INCONCLUSIVE', utc=stage_review.utc(),
                  close_sent=False, wake_sent=False, causal_pass=False)
    rc = 3
    try:
        need(endpoint == (wb.HOST, str(wb.PORT), wb.USER), 'unpaired endpoint')
        path = Path.home()/'.ssh'/PROFILE_NAME
        report['status'] = preflight(report, path)
        if report['status'] == 'PREFLIGHT_READY_OWNER_CLOSE_ONLY':
            rc = 0
    except Exception as exc:
        report['error'] = type(exc).__name__+': '+ascii(str(exc)[:160])
    outdir = ROOT/'wake-acceptance/evidence'
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir/('PREFLIGHT-'+str(time.time_ns())+'.json')
    stage_review.store(out, report)
    report['record'] = str(out)
    print(json.dumps(report, ensure_ascii=True) if args.json else report['status']+' '+str(out))
    return rc
