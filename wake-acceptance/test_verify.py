import contextlib
import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import verify as v

# All host tests are network-disabled. The synthetic outputs use the actual WB wire grammar.
PIN, SID0, SID1 = 'a'*64, 'b'*64, 'c'*64
R0, R1, B = '0123456789ABCDEF', '0123456789ABCDE0', '01.78-live-saveprobe'


class Shell:
    def __init__(self, run=R1, pin=PIN):
        self.version, self.host_pin, self.transport_id = '01.78', pin, SID1
        self.calls = []
        self.replies = [
            f'wb version=01.78 build={B} abi=3 proto=wb10 run={run} payload=none uptime_ms=1000',
            f'run={run} uptime_ms=1001 ssh=connected cmds=1 payload=none core=01.78 last_install=none peer=192.0.2.10:2222',
            f'wb version=01.78 build={B} abi=3 proto=wb10 run={run} payload=none uptime_ms=1002',
        ]

    def one(self, cmd):
        self.calls.append(cmd)
        response = self.replies.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class Cases(unittest.TestCase):
    def setUp(self):
        trap = mock.patch.object(socket, 'socket', side_effect=AssertionError('forbidden real network in host tests'))
        trap.start()
        self.addCleanup(trap.stop)
        self.t = Shell()
        self.baseline = dict(identity=dict(version='01.78', build=B, run=R0, channel='one interactive PTY',
                                           host_sha256=PIN, transport_sha256=SID0))
        self.log = dict(events=[], causal_pass=False, wake_sent=False)
        self.count = 0

    @contextlib.contextmanager
    def connect(self):
        self.count += 1
        yield self.t

    def drive(self, phase='after', pin_check=lambda: None):
        return v.observe(phase, self.baseline if phase=='after' else None, PIN, pin_check, self.connect, self.log)

    def test_changed_run_is_only_observation(self):
        self.assertEqual(self.drive(), v.NEW)
        self.assertFalse(self.log['causal_pass'])
        self.assertFalse(self.log['wake_sent'])
        self.assertEqual(self.t.calls, ['ver','status','ver'])
        self.assertEqual(self.count,1)
        self.assertEqual([x['transport_sha256'] for x in self.log['events']], [SID1]*3)

    def test_preclose_snapshot(self):
        self.assertEqual(self.drive('before'), v.BEFORE)
        self.assertEqual(self.log['sample']['run'], R1)

    def test_same_run_not_relaunched(self):
        self.t=Shell(R0)
        self.assertEqual(self.drive(), 'SAME_RUN_NOT_RELAUNCHED')

    def test_wrong_host_is_not_queried(self):
        self.t.host_pin = 'd'*64
        with self.assertRaisesRegex(ValueError, 'wrong server'): self.drive()
        self.assertEqual(self.t.calls, [])

    def test_changed_local_pin_before_connect(self):
        def wrong(): raise ValueError('changed local pin')
        with self.assertRaisesRegex(ValueError, 'changed local'): self.drive(pin_check=wrong)
        self.assertEqual(self.count,0)

    def test_saved_pin_replaced_during_sample(self):
        calls = iter([True,True,False])
        with self.assertRaisesRegex(ValueError,'changed'):
            self.drive(pin_check=lambda: v.need(next(calls), 'changed'))

    def test_status_different_run(self):
        self.t.replies[1] = self.t.replies[1].replace(R1,R0)
        with self.assertRaises(ValueError): self.drive()

    def test_status_disconnected(self):
        self.t.replies[1] = self.t.replies[1].replace('ssh=connected','ssh=disconnected')
        with self.assertRaises(ValueError): self.drive()

    def test_regressed_uptime(self):
        self.t.replies[-1]=self.t.replies[-1].replace('1002','999')
        with self.assertRaises(ValueError): self.drive()

    def test_stale_baseline_build(self):
        self.baseline['identity']['build']='01.78-other'
        with self.assertRaisesRegex(ValueError,'core changed'): self.drive()

    def test_same_transport(self):
        self.baseline['identity']['transport_sha256']=SID1
        with self.assertRaisesRegex(ValueError,'same transport'): self.drive()

    def test_leak_across_transports(self):
        real=self.t.one
        def wrong(cmd):
            self.t.transport_id = 'e'*64
            return real(cmd)
        self.t.one=wrong
        with self.assertRaisesRegex(ValueError,'session'): self.drive()

    def test_disconnect_is_not_wake(self):
        self.t.replies[1]=ConnectionResetError()
        with self.assertRaises(ConnectionResetError): self.drive()
        self.assertFalse(self.log['causal_pass'])

    def test_error_reply(self):
        self.t.replies[1]='ERR denied'
        with self.assertRaises(ValueError): self.drive()

    def test_preserved_real_recovery_as_baseline(self):
        a=v.anchor(); b=v.load_baseline(v.RECOVERY,a)
        self.assertEqual(b['identity']['run'],a['run'])
        self.assertIn('not a fresh', b['source'])

    def test_input_report_is_replayed_not_trusted_by_label(self):
        self.drive('before')
        rec=dict(schema='wb.wake.identity.v1',origin='live-pinned-pty',phase='before',
                 baseline=None,result=v.BEFORE,**self.log)
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'before.json'
            def load(j):
                f.write_text(json.dumps(j),encoding='utf-8')
                return v.load_baseline(f,{'host_pin':PIN})
            self.assertEqual(load(rec)['identity']['build'],B)
            for case in ['run','session','command','stdout','incomplete','phase','origin','oversize']:
                with self.subTest(case=case):
                    j=copy.deepcopy(rec)
                    if case=='run': j['sample']['run'] = R0
                    elif case=='session': j['events'][1]['transport_sha256'] = SID0
                    elif case=='command': j['events'][1]['command'] = 'open'
                    elif case=='stdout': j['events'][1]['output'] += '\n'
                    elif case=='incomplete': j['events'].pop()
                    elif case=='phase': j['phase'] = 'after'
                    elif case=='origin': j['origin'] = 'fixture'
                    elif case=='oversize': j['extra'] = 'x'*70000
                    with self.assertRaises(ValueError): load(j)

if __name__ == '__main__': unittest.main(verbosity=2)
