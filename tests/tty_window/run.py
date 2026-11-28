"""Deterministic offline peers only. No socket, SSH, Vita or Jetson operations."""
from __future__ import annotations

from collections import deque
import hashlib
import contextlib, io
from unittest import mock
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE.parents[1] / 'tools'))
import wb_tree
from wbterm import CHUNK, ROOT_PROMPT, Inconclusive, Refused, Terminal
import wbterm as w

def push_windowed(term, source, remote, *, window=8, progress=None):
    class Meter:
        def update(self, *args):
            if progress: progress(*args)
        def finish(self): pass
    with mock.patch.object(w, 'TransferMeter', Meter):
        return Terminal.push(term, source, remote, window=window)

REMOTE = 'ux0:/data/pipeline test.bin'


class FakePeer:
    """Model native serialized ACKs; enforce no-clobber and END-after-ACK.

    A reply becomes consumed only in reply(), distinct from receiving a frame.
    This makes window occupancy and END ordering observable deterministically.
    """
    def __init__(self, *, version='02.11', failure=None, on_send=None, on_ack=None):
        self.version = version
        self.failure = failure
        self.on_send = on_send
        self.on_ack = on_ack
        self.events = []
        self.pending = deque()
        self.data = bytearray()
        self.max_pending = 0
        self.end = False
        self.ready = False
        self.commands = 0
        self.ack_count = 0

    def require_transfer(self):
        self.events.append(('require_transfer',))
        if self.version < '01.65':
            raise Refused('this shell predates PTY file transfers; no fallback')

    def command(self, text):
        self.commands += 1
        self.events.append(('command', text))
        m = re.fullmatch(r'put "ux0:/data/pipeline test.bin" (\d+) sha256=([0-9a-f]{64})', text)
        assert m, text
        self.size, self.sha = int(m[1]), m[2]
        self.ready = True

    def send(self, text):
        if text == 'END':
            assert not self.pending, 'END preceded final ACK consumption'
            assert len(self.data) == self.size, 'END preceded all data'
            self.end = True
            self.events.append(('send_END', self.ack_count))
            if self.failure == 'timeout_send_END':
                raise TimeoutError('fixture END write outcome unknown')
            if self.failure == 'eof_send_END':
                raise EOFError('fixture closed after END bytes')
            return
        m = re.fullmatch(r'D (\d+) ([0-9a-f]+)', text)
        assert m, text
        data = bytes.fromhex(m[2])
        assert int(m[1]) == len(self.data)
        assert 0 < len(data) <= CHUNK
        self.data.extend(data)
        assert len(self.data) <= self.size
        self.pending.append(len(self.data))
        self.max_pending = max(self.max_pending, len(self.pending))
        self.events.append(('send_D', int(m[1]), len(data)))
        if self.on_send:
            self.on_send(self)

    def reply(self):
        if self.ready:
            self.ready = False
            self.events.append(('read_READY',))
            if self.failure == 'no_clobber':
                raise w.DeviceRefused('Vita refused: destination-exists')
            if self.failure == 'bad_READY':
                return f'TTY1 READY PUT {self.size} 4096'
            return f'TTY1 READY PUT {self.size} {CHUNK}'
        if not self.end:
            assert self.pending
            expected = self.pending[0]
            self.events.append(('read_ACK', expected))
            if self.failure == 'missing_ACK':
                raise TimeoutError('fixture ACK lost')
            if self.failure == 'eof_ACK':
                raise Inconclusive('terminal closed before expected receipt')
            if self.failure == 'refused_ACK':
                raise w.DeviceRefused('Vita refused: upload write failure')
            self.pending.popleft()
            self.ack_count += 1
            if self.on_ack:
                self.on_ack(self)
            if self.failure == 'wrong_ACK':
                return f'TTY1 ACK {expected + 1}'
            if self.failure == 'duplicate_ACK' and self.ack_count == 2:
                return 'TTY1 ACK 2048'
            if self.failure == 'out_of_order_ACK':
                return f'TTY1 ACK {expected + CHUNK}'
            return f'TTY1 ACK {expected}'
        self.events.append(('read_FINAL',))
        if self.failure == 'lost_FINAL':
            raise TimeoutError('fixture final receipt lost')
        if self.failure == 'eof_FINAL':
            raise Inconclusive('terminal closed before expected receipt')
        if self.failure == 'refused_FINAL':
            raise w.DeviceRefused('Vita refused: final readback hash mismatch')
        if self.failure == 'bad_FINAL':
            return f'TTY1 OK PUT {self.size} ' + '0' * 64
        assert hashlib.sha256(self.data).hexdigest() == self.sha
        return f'TTY1 OK PUT {self.size} {self.sha}'

    def exact(self, token):
        assert token == ROOT_PROMPT and self.end
        self.events.append(('read_PROMPT',))
        if self.failure == 'malformed_PROMPT':
            raise Refused('unexpected terminal prompt or echo')
        if self.failure == 'lost_PROMPT':
            raise TimeoutError('fixture prompt lost')


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=HERE, prefix='fixture-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'source.bin'

    def source(self, size=CHUNK * 4 + 13):
        data = (bytes(range(256)) * ((size + 255) // 256))[:size]
        self.path.write_bytes(data)
        return wb_tree.FileSource(self.path, size, hashlib.sha256(data).hexdigest(),
                                  wb_tree.signature(self.path.stat()))

    def run_peer(self, size=CHUNK * 4 + 13, window=8, **kwargs):
        source = self.source(size)
        peer = FakePeer(**kwargs)
        samples = []
        result = push_windowed(peer, source, REMOTE, window=window,
                               progress=lambda *s: samples.append(s))
        self.assertEqual(result, dict(action='put', remote=REMOTE, bytes=size,
                                      sha256=source.sha256))
        self.assertEqual(bytes(peer.data), self.path.read_bytes())
        self.assertEqual(samples[-1], ('PUT', size, size))
        self.assertEqual(peer.commands, 1)
        return peer, samples

    def test_window_one_is_stop_and_wait(self):
        peer, _ = self.run_peer(window=1)
        data_events = [e[0] for e in peer.events if e[0] in ('send_D', 'read_ACK')]
        self.assertEqual(data_events, ['send_D', 'read_ACK'] * 5)
        self.assertEqual(peer.max_pending, 1)

    def test_window_eight_sends_before_reads_and_is_bounded(self):
        peer, _ = self.run_peer(size=CHUNK * 19 + 7, window=8)
        events = [e[0] for e in peer.events if e[0] in ('send_D', 'read_ACK')]
        self.assertEqual(events[:8], ['send_D'] * 8)
        self.assertEqual(events[8], 'read_ACK')
        self.assertEqual(peer.max_pending, 8)

    def test_all_supported_windows_and_sizes(self):
        for window in (1, 2, 4, 8, 16):
            for size in (0, 1, CHUNK, CHUNK + 1, CHUNK * 17 + 3):
                with self.subTest(window=window, size=size):
                    peer, _ = self.run_peer(size=size, window=window)
                    self.assertLessEqual(peer.max_pending, window)
                    self.assertEqual(peer.ack_count, (size + CHUNK - 1) // CHUNK)

    def test_invalid_windows_fail_before_protocol(self):
        source = self.source()
        for window in (0, -1, 17, True, 1.0, '8'):
            with self.subTest(window=window):
                peer = FakePeer()
                with self.assertRaises(Refused):
                    push_windowed(peer, source, REMOTE, window=window)
                self.assertEqual(peer.events, [])

    def test_cli_entry_default_and_explicit_window(self):
        source = self.source(CHUNK * 11 + 29)
        cases = [('02.12', [], 8), ('02.12', ['--window','1'], 1),
                 ('02.11', [], 1), ('02.11', ['--window','4'], 4)]
        for ver, options, expected in cases:
            with self.subTest(ver=ver, options=options):
                class CliPeer(FakePeer):
                    push = Terminal.push
                peer = CliPeer(version=ver)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(w, 'paired_terminal', return_value=contextlib.nullcontext(peer)), \
                     mock.patch.object(sys, 'argv', ['wbterm','push',str(source.path),REMOTE]+options), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(w.main(),0)
                self.assertEqual(peer.max_pending,expected)
                self.assertEqual(json.loads(out.getvalue())['sha256'],source.sha256)
                self.assertIn('PUT [',err.getvalue())
                self.assertIn('ETA',err.getvalue())
                self.assertNotIn('TTY1 ACK',err.getvalue())

    def test_invalid_cli_window_before_open(self):
        with mock.patch.object(w, 'paired_terminal') as open_term, \
             mock.patch.object(sys, 'argv', ['wbterm','push','local',REMOTE,'--window','17']), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            try: w.main()
            finally: open_term.assert_not_called()

    def test_old_peer_cannot_force_window(self):
        peer = FakePeer(version='02.10')
        with self.assertRaises(Refused):
            push_windowed(peer, self.source(), REMOTE)
        self.assertFalse(peer.events)
        
    def test_rejects_unquoted_unsafe_paths_before_command(self):
        source = self.source()
        for remote in ('ux0:/../bad', 'ux0:/data/a;exit', 'ux0:/data/a\nEND', 'uma0:/data/a'):
            with self.subTest(remote=remote):
                peer = FakePeer()
                with self.assertRaises(Refused):
                    push_windowed(peer, source, remote)
                self.assertEqual(peer.commands, 0)

    def test_empty_file_requires_supported_version(self):
        source = self.source(0)
        peer = FakePeer(version='01.65')
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE, window=1)
        self.assertEqual(peer.commands, 0)

    def test_changed_snapshot_rejected_before_command(self):
        source = self.source()
        self.path.write_bytes(b'replaced')
        peer = FakePeer()
        with self.assertRaises(wb_tree.TreeError):
            push_windowed(peer, source, REMOTE)
        self.assertEqual(peer.commands, 0)

    def test_snapshot_hash_mismatch_rejected_before_command(self):
        source = self.source()
        source = wb_tree.FileSource(source.path, source.size, '0' * 64, source.sig)
        peer = FakePeer()
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE)
        self.assertEqual(peer.commands, 0)

    def test_ready_refusal_and_no_clobber_never_send_data(self):
        source = self.source()
        for failure in ('bad_READY', 'no_clobber'):
            with self.subTest(failure=failure):
                peer = FakePeer(failure=failure)
                with self.assertRaises(Refused):
                    push_windowed(peer, source, REMOTE)
                self.assertEqual(peer.data, b'')
                self.assertFalse(peer.end)
                self.assertEqual(peer.commands, 1)

    def test_wrong_missing_duplicate_ordered_or_refused_ack_never_end(self):
        source = self.source()
        for failure in ('wrong_ACK', 'missing_ACK', 'duplicate_ACK',
                        'out_of_order_ACK', 'refused_ACK'):
            with self.subTest(failure=failure):
                peer = FakePeer(failure=failure)
                with self.assertRaises((Refused, TimeoutError)):
                    push_windowed(peer, source, REMOTE, window=2)
                self.assertFalse(peer.end)
                self.assertEqual(peer.commands, 1)
                self.assertLessEqual(peer.max_pending, 2)

    def test_truncated_source_never_end(self):
        source = self.source(CHUNK * 20)
        def truncate(peer):
            if len(peer.data) == CHUNK:
                self.path.write_bytes(b'x')
        peer = FakePeer(on_send=truncate)
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE, window=8)
        self.assertFalse(peer.end)

    def test_ack_eof_never_end_or_retry(self):
        source = self.source()
        peer = FakePeer(failure='eof_ACK')
        with self.assertRaisesRegex(Inconclusive, 'closed before expected receipt'):
            push_windowed(peer, source, REMOTE)
        self.assertFalse(peer.end)
        self.assertEqual(peer.commands, 1)

    def test_source_changed_on_final_ack_never_end(self):
        source = self.source()
        def mutate(peer):
            if peer.pending or len(peer.data) != source.size:
                return
            self.path.write_bytes(b'X' * source.size)
        peer = FakePeer(on_ack=mutate)
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE, window=8)
        self.assertFalse(peer.end)

    def test_actual_sent_hash_detects_content_change_even_restored_signature(self):
        source = self.source(CHUNK * 40)
        before = self.path.stat()
        def mutate(peer):
            if len(peer.data) == CHUNK:
                with self.path.open('r+b') as file:
                    file.seek(CHUNK * 20)
                    file.write(b'X' * CHUNK)
                os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
                self.assertEqual(wb_tree.signature(self.path.stat()), source.sig)
        peer = FakePeer(on_send=mutate)
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE, window=8)
        self.assertFalse(peer.end)

    def test_lost_or_wrong_final_receipt_or_prompt_is_inconclusive(self):
        source = self.source()
        for failure in ('lost_FINAL', 'eof_FINAL', 'bad_FINAL', 'lost_PROMPT',
                        'timeout_send_END', 'eof_send_END', 'malformed_PROMPT'):
            with self.subTest(failure=failure):
                peer = FakePeer(failure=failure)
                with self.assertRaisesRegex(Inconclusive, 'completion unknown.*do not auto-retry'):
                    push_windowed(peer, source, REMOTE)
                self.assertTrue(peer.end)
                self.assertEqual(peer.commands, 1)

    def test_native_final_refusal_is_not_success_or_retry(self):
        source = self.source()
        peer = FakePeer(failure='refused_FINAL')
        with self.assertRaises(Refused):
            push_windowed(peer, source, REMOTE)
        self.assertTrue(peer.end)
        self.assertEqual(peer.commands, 1)

    def test_end_only_after_final_ack_and_progress_is_acknowledged(self):
        peer, samples = self.run_peer(size=CHUNK * 17 + 7, window=16)
        events = peer.events
        end_index = next(i for i, e in enumerate(events) if e[0] == 'send_END')
        self.assertEqual(events[end_index - 1], ('read_ACK', CHUNK * 17 + 7))
        puts = [s[1] for s in samples if s[0] == 'PUT']
        self.assertEqual(puts, [0] + [min(i * CHUNK, CHUNK * 17 + 7) for i in range(1, 19)])

    def test_rollback_same_function_window_one(self):
        baseline, _ = self.run_peer(window=1)
        modified, _ = self.run_peer(window=8)
        rollback, _ = self.run_peer(window=1)
        self.assertEqual(baseline.events, rollback.events)
        self.assertEqual(hashlib.sha256(baseline.data).hexdigest(),
                         hashlib.sha256(modified.data).hexdigest())
        self.assertEqual((baseline.max_pending, modified.max_pending, rollback.max_pending), (1, 5, 1))


def scheduling_evidence():
    """Machine-readable host-only ordering evidence, not a throughput benchmark."""
    with tempfile.TemporaryDirectory(dir=HERE, prefix='evidence-') as tmp:
        path = Path(tmp) / 'source.bin'
        data = bytes(range(256)) * 81 + b'last'
        path.write_bytes(data)
        source = wb_tree.FileSource(path, len(data), hashlib.sha256(data).hexdigest(),
                                    wb_tree.signature(path.stat()))
        result = {}
        for label, window in [('BASELINE', 1), ('MODIFIED', 8), ('ROLLBACK', 1)]:
            peer = FakePeer()
            receipt = push_windowed(peer, source, REMOTE, window=window)
            events = [e[0] for e in peer.events if e[0] in ('send_D', 'read_ACK', 'send_END')]
            result[label] = dict(window=window, max_outstanding=peer.max_pending,
                                 first_events=events[:18], final_events=events[-4:],
                                 commands=peer.commands, final_receipt=receipt,
                                 exit_status=0)
        return result


if __name__ == '__main__':
    if '--evidence' in sys.argv:
        print(json.dumps(scheduling_evidence(), indent=2))
    else:
        unittest.main(verbosity=2)
