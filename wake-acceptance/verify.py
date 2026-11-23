"""Read-only WB session observation; never sends a wake request or asserts its cause."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
PROJECT = D.parents[1]
# Use the *verified predecessor's* PTY/host-key/owner-key client, not candidate code.
sys.path.insert(0, str(PROJECT / 'v1.78' / 'tools'))
import wbterm as wb

RECOVERY = PROJECT / 'iterations/install-0178-saveprobe/r1/recovery-144132237537.json'
ANCHOR_HASH = '700c201f5e494f7f5e312897a47145951b6bb3c311f257b6bf6d30e7cb8d7b7e'
CMDS = ('ver', 'status', 'ver')
BEFORE = 'PRECLOSE_WB_IDENTITY_OBSERVED'
NEW = 'NEW_RUN_ON_ORIGINAL_PIN_OBSERVED_NOT_PROOF_OF_WAKE'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(buf):
    return hashlib.sha256(buf).hexdigest()


def anchor():
    data = RECOVERY.read_bytes()
    need(sha(data) == ANCHOR_HASH, 'pre-existing 01.78 verified receipt changed')
    receipt = json.loads(data)
    need(receipt['result'] == 'VERIFIED_01.78_AND_MATCHING_R1_PROOF', 'invalid anchor')
    return receipt['returned_identity']


def identity(i, pin):
    need(isinstance(i, dict) and i.get('host_sha256') == pin and
         re.fullmatch(r'[0-9a-f]{64}', pin) and i.get('channel') == 'one interactive PTY',
         'wrong trust anchor or not one PTY')
    for field, pattern in [('version', r'[0-9]{2}\.[0-9]{2}'),
                           ('run', r'[0-9A-F]{16}'),
                           ('transport_sha256', r'[0-9a-f]{64}')]:
        need(isinstance(i.get(field), str) and re.fullmatch(pattern, i[field]), 'bad '+field)
    need(isinstance(i.get('build'), str) and re.fullmatch(re.escape(i['version'])+r'-[A-Za-z0-9._-]{1,64}', i['build']),
         'bad versioned build tag')
    return i


def saved_pin_matches(a):
    path, saved = wb.pin.canonical_saved(wb.pin.pin_path(wb.HOST, wb.PORT), wb.HOST, wb.PORT)
    need(saved == a['host_pin'] and sha(path.read_bytes()) == a['pin_file_sha256'],
         'existing saved public pin does not match previous acceptance; not re-pairing')


def load_baseline(path, a):
    with path.open('rb') as f:
        data = f.read(65537)
    need(len(data) <= 65536, 'oversized baseline')
    record = json.loads(data)
    if sha(data) == ANCHOR_HASH:
        old = a
        i = dict(version=old['version'], build=old['build'], run=old['run'],
                 transport_sha256=old['transport_sha256'], host_sha256=old['host_pin'],
                 channel='one interactive PTY')
        source = 'historical verified recovery, not a fresh close witness'
    else:
        need(record.get('schema') == 'wb.wake.identity.v1' and record.get('result') == BEFORE
             and record.get('phase') == 'before' and record.get('origin') == 'live-pinned-pty'
             and record.get('baseline') is None, 'not a pre-close identity observation')
        i = identity(record['sample'], a['host_pin'])
        need(replay(record['events'], i) == i, 'baseline transcript does not match its identity')
        source = 'pre-close identity observation, not a close witness'
    return dict(identity=identity(i, a['host_pin']), sha256=sha(data), source=source)


class Tap:
    """Limit transmitted strings; use original wbterm validator on the literal outputs."""
    def __init__(self, term, events):
        self.term, self.events = term, events
        self.host_pin, self.transport_id, self.version = term.host_pin, term.transport_id, term.version

    def one(self, cmd):
        need(len(self.events) < len(CMDS) and cmd == CMDS[len(self.events)], 'non-observation command')
        need(self.term.transport_id == self.transport_id, 'transport changed')
        reply = self.term.one(cmd)
        need(self.term.transport_id == self.transport_id and len(reply) < 1024 and reply.isascii()
             and reply.isprintable(), 'unexpected session or unsafe reply')
        self.events.append(dict(command=cmd, output=reply, transport_sha256=self.transport_id))
        return reply


def replay(events, i):
    need(isinstance(events, list) and len(events) == 3, 'incomplete transcript')
    class Recorded:
        host_pin = i['host_sha256']
        transport_id = i['transport_sha256']
        version = i['version']
        def one(self, command):
            item = next(entries)
            need(item['command'] == command and item['transport_sha256'] == self.transport_id,
                 'wrong command or transport in transcript')
            need(isinstance(item['output'], str) and len(item['output']) < 1024
                 and item['output'].isascii() and item['output'].isprintable(), 'malformed output')
            return item['output']
    entries = iter(events)
    return wb.Terminal.check(Recorded())


def observe(phase, baseline, trusted, verify_pin, paired, report):
    need(phase in ('before', 'after') and (phase == 'after') == (baseline is not None), 'baseline/phase mismatch')
    old = identity(baseline['identity'], trusted) if baseline else None
    verify_pin()
    with paired() as term:
        need(term.host_pin == trusted, 'wrong server identity')
        verify_pin()
        sample = identity(wb.Terminal.check(Tap(term, report['events'])), trusted)
        need(replay(report['events'], sample) == sample, 'session transcript inconsistent')
        verify_pin()
    report['sample'] = sample
    if old is None:
        return BEFORE
    need((sample['version'], sample['build']) == (old['version'], old['build']), 'core changed; not wake-only')
    need(sample['transport_sha256'] != old['transport_sha256'], 'same transport as pre-close; not a new connection')
    return NEW if sample['run'] != old['run'] else 'SAME_RUN_NOT_RELAUNCHED'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['before', 'after'])
    p.add_argument('--baseline', type=Path, help='required for after; before observation or verified 01.78 predecessor recovery')
    p.add_argument('--live', action='store_true', required=True, help='one pinned read-only connection; no retry')
    args = p.parse_args()
    if (args.phase == 'after') != bool(args.baseline):
        p.error('only after requires --baseline')
    stamp = dt.datetime.now(dt.timezone.utc)
    report = dict(schema='wb.wake.identity.v1', origin='live-pinned-pty', utc=stamp.isoformat(),
                  phase=args.phase, baseline=None, events=[], result='INCONCLUSIVE', wake_sent=False,
                  causal_pass=False, endpoint=f'{wb.HOST}:{wb.PORT}')
    rc = 2
    try:
        a = anchor()
        b = load_baseline(args.baseline, a) if args.baseline else None
        report['baseline'] = b
        report['result'] = observe(args.phase, b, a['host_pin'], lambda: saved_pin_matches(a), wb.paired_terminal, report)
        rc = 0 if report['result'] in (BEFORE, NEW) else 3
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + ascii(str(exc)[:260])
    out = D / 'evidence' / ('DEVICE-'+stamp.strftime('%Y%m%dT%H%M%S%fZ')+'.json')
    out.parent.mkdir(exist_ok=True)
    with out.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=True)
        f.write('\n')
    print(report['result'], report.get('error',''), out)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
