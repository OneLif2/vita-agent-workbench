"""Offline read-only game-log collector tests. No socket, Vita or owner keys."""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import game_logs as logs


def row(name, data=None, *, directory=False, modified='2026-11-24 19:30'):
    mode = 'drwxr-xr-x' if directory else '-rw-r--r--'
    size = '-' if directory else str(len(data))
    return f'{mode} {size:>12} {modified:<16} {name}{"/" if directory else ""}'.encode('ascii')


class Channel:
    def __init__(self): self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)


class Terminal:
    version = '02.10'
    host_pin = 'a' * 64
    transport_id = 'b' * 64
    def __init__(self, tree=None, *, title=logs.TITLE):
        self.remote_root, self.version = logs.target_for(title)
        self.tree = tree if tree is not None else {'fps.log': b'fps=60\n', 'nested': {'audio.bin': b'\x00\xff\n', 'empty.log': b''}, 'empty dir': {}}
        self.commands = []
        self.buf = bytearray()
        self.ch = Channel()
        self.checks = 0
        self.list_calls = {}
        self.bad_rows = None
        self.fail_remote = None
        self.wrong_receipt = False
        self.change_listing = False
        self.before_pull = None
        self.bad_identity = False
        self.read_fragments = []
        self.fragment = False
    def identity(self):
        return dict(version=self.version, build=self.version+'-fixture', run='0123456789ABCDEF',
                    channel='one interactive PTY', host_sha256=self.host_pin, transport_sha256=self.transport_id)
    def check(self):
        self.checks += 1
        result = self.identity()
        if self.bad_identity and self.checks > 1: result['run'] = 'FEDCBA9876543210'
        return result
    def node(self, remote):
        assert remote == self.remote_root or remote.startswith(self.remote_root + '/')
        node = self.tree
        for part in remote[len(self.remote_root):].strip('/').split('/'):
            if part: node = node[part]
        return node
    def command(self, command):
        assert command.startswith('ls -l "') and command.endswith('"')
        self.commands.append(command)
        remote = command[len('ls -l "'):-1]
        self.list_calls[remote] = self.list_calls.get(remote, 0) + 1
        if self.bad_rows is not None:
            rows = self.bad_rows
        else:
            node = self.node(remote)
            rows = [row(name, data, directory=isinstance(data, dict)) for name, data in node.items()]
            if self.change_listing and self.list_calls[remote] > 1: rows.append(row('new.log', b'changed'))
        wire = b''.join(r + b'\r\n' for r in rows) + logs.wb.ROOT_PROMPT
        if self.fragment:
            self.read_fragments = [wire[i:i+3] for i in range(0, len(wire), 3)]
            self.buf.clear()
        else:
            self.buf = bytearray(wire)
    def _more(self):
        if not self.read_fragments: raise EOFError('fragmented listing ended')
        self.buf.extend(self.read_fragments.pop(0))
    def exact(self, token):
        while len(self.buf) < len(token): self._more()
        assert self.buf.startswith(token)
        del self.buf[:len(token)]
    def line(self):
        while b'\n' not in self.buf: self._more()
        n = self.buf.index(10) + 1
        raw = bytes(self.buf[:n]); del self.buf[:n]
        assert raw.endswith(b'\r\n')
        return raw[:-2]
    def pull(self, remote, local, max_bytes):
        self.commands.append('get ' + logs.wb.quoted_path(remote))
        if self.before_pull: self.before_pull(Path(local))
        if remote == self.fail_remote: raise EOFError('simulated lost transfer')
        data = self.node(remote)
        assert isinstance(data, bytes) and len(data) <= max_bytes
        with Path(local).open('xb') as f: f.write(data)
        return dict(action='get', remote=remote, local=str(Path(local).absolute()), bytes=len(data),
                    sha256=('0' * 64 if self.wrong_receipt else hashlib.sha256(data).hexdigest()))


class Paired:
    def __init__(self, terminal): self.terminal = terminal; self.opened = 0; self.closed = 0
    @contextlib.contextmanager
    def __call__(self):
        self.opened += 1
        try: yield self.terminal
        finally: self.closed += 1


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wb-game-logs-host-')
        self.base = Path(self.tmp.name)
        self.out = self.base / 'new'
    def tearDown(self): self.tmp.cleanup()
    def collect(self, terminal, **kw):
        paired = Paired(terminal)
        result = logs.collect(self.out, paired=paired, **kw)
        self.assertEqual((paired.opened, paired.closed), (1, 1))
        return result
    def fails(self, terminal, **kw):
        paired = Paired(terminal)
        with self.assertRaises(logs.PartialCollection) as caught:
            logs.collect(self.out, paired=paired, **kw)
        report = json.loads((self.out / logs.REPORT).read_bytes())
        self.assertFalse(report['complete'])
        self.assertEqual(report, caught.exception.report)
        self.assertEqual((paired.opened, paired.closed), (1, 1))
        return report
    def test_binary_empty_nested_dirs_single_pinned_connection_and_receipts(self):
        terminal = Terminal(); terminal.fragment = True
        result = self.collect(terminal)
        self.assertTrue(result['complete'])
        self.assertFalse(result['device_writes'])
        self.assertFalse(result['atomic_remote_snapshot'])
        self.assertIn('not every underlying', result['scope'])
        self.assertEqual(result['files_verified'], 3)
        self.assertEqual(result['bytes_confirmed'], 10)
        self.assertEqual((self.out / 'Logs/nested/audio.bin').read_bytes(), b'\x00\xff\n')
        self.assertEqual((self.out / 'Logs/nested/empty.log').read_bytes(), b'')
        self.assertTrue((self.out / 'Logs/empty dir').is_dir())
        self.assertEqual(terminal.checks, 2)
        self.assertTrue(all(c.startswith(('ls -l ', 'get ')) for c in terminal.commands))
        self.assertEqual(set(terminal.list_calls.values()), {2})
        self.assertTrue(all(e['complete'] for e in result['commands']))
        self.assertTrue(any(e.get('stdout_lines') for e in result['commands']))
        self.assertEqual(json.loads((self.out / logs.REPORT).read_bytes()), result)
    def test_empty_root_success(self):
        result = self.collect(Terminal({}))
        self.assertEqual(result['files_verified'], 0)
        self.assertTrue((self.out / 'Logs').is_dir())
    def test_perflab_recursive_binary_sha_and_single_selected_pty(self):
        terminal = Terminal(title='RJGP52237'); terminal.fragment = True
        result = self.collect(terminal, title='RJGP52237')
        self.assertEqual(result['title'], 'RJGP52237')
        self.assertEqual(result['remote'], 'ux0:/data/RJGP52237/Logs')
        self.assertEqual(result['identity']['version'], '02.11')
        self.assertEqual(result['files_verified'], 3)
        self.assertEqual(result['bytes_confirmed'], 10)
        self.assertEqual(terminal.checks, 2)
        self.assertTrue(all('ux0:/data/RJGP52237/Logs' in c for c in terminal.commands))
        self.assertTrue(all('RJGM52237' not in c for c in terminal.commands))
        self.assertEqual((self.out / 'Logs/nested/audio.bin').read_bytes(), b'\x00\xff\n')
        for receipt in result['receipts']:
            self.assertTrue(receipt['remote'].startswith(result['remote'] + '/'))
            self.assertEqual(hashlib.sha256(Path(receipt['local']).read_bytes()).hexdigest(), receipt['sha256'])
    def test_perflab_selection_does_not_mutate_default_rjgm_target(self):
        first = self.collect(Terminal({'bench.log': b'p'}, title='RJGP52237'), title='RJGP52237')
        self.out = self.base / 'second'
        second = self.collect(Terminal({'game.log': b'm'}))
        self.assertEqual(first['title'], 'RJGP52237')
        self.assertEqual(second['title'], 'RJGM52237')
        self.assertEqual(second['remote'], logs.REMOTE_ROOT)
        self.assertEqual(logs.TITLE, 'RJGM52237')
        self.assertEqual(logs.REMOTE_ROOT, 'ux0:/data/RJGM52237/Logs')
    def test_perflab_on_0210_refused_before_any_listing_or_get(self):
        terminal = Terminal(title='RJGP52237'); terminal.version = '02.10'
        result = self.fails(terminal, title='RJGP52237')
        self.assertIn('02.11', result['reason'])
        self.assertEqual(terminal.commands, [])
        self.assertEqual(result['receipts'], [])
    def test_unsupported_title_refused_before_filesystem_or_ssh(self):
        for title in ('RJGP52238', 'rjgp52237', 'RJGP52237/../INAP00018', '', None):
            paired = Paired(Terminal())
            with self.assertRaises(logs.Problem): logs.collect(self.out, title=title, paired=paired)
            self.assertEqual(paired.opened, 0)
            self.assertFalse(self.out.exists())
    def test_cross_title_and_arbitrary_root_refused_without_dispatch(self):
        rjgm = logs.REMOTE_ROOT; rjgp = logs.target_for('RJGP52237')[0]
        self.assertEqual(logs.remote_child(rjgp, 'bench.log', root=rjgp), rjgp+'/bench.log')
        for root, remote in ((rjgp, rjgm), (rjgm, rjgp), ('ux0:/data/INAP00018', 'ux0:/data/INAP00018')):
            terminal = Terminal()
            with self.assertRaises(logs.Problem): logs.remote_child(remote, 'a.log', root=root)
            with self.assertRaises(logs.Problem): logs.listing(terminal, remote, root=root)
            self.assertEqual(terminal.commands, [])
    def test_cli_perflab_choice_forwarded_and_unknown_title_rejected(self):
        with mock.patch.object(logs, 'collect', return_value={'complete':True}) as collect, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(logs.main(['--out', str(self.out), '--title', 'RJGP52237']), 0)
            self.assertEqual(collect.call_args.kwargs['title'], 'RJGP52237')
        with mock.patch.object(logs, 'collect') as collect, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error: logs.main(['--out', str(self.out), '--title', 'INAP00018'])
            self.assertEqual(error.exception.code, 2)
            collect.assert_not_called()
    def test_more_than32_rows_not_silently_truncated(self):
        tree = {f'{n:03d}.log': bytes([n]) for n in range(64)}
        result = self.collect(Terminal(tree))
        self.assertEqual(result['files_verified'], 64)
        self.assertEqual(result['bytes_confirmed'], 64)
    def test_existing_destination_refused_before_ssh(self):
        self.out.mkdir(); (self.out / 'keep').write_bytes(b'pristine')
        paired = Paired(Terminal())
        with self.assertRaises(logs.Problem): logs.collect(self.out, paired=paired)
        self.assertEqual(paired.opened, 0)
        self.assertEqual((self.out / 'keep').read_bytes(), b'pristine')
    def test_parent_traversal_output_refused_before_ssh(self):
        paired = Paired(Terminal())
        with self.assertRaises(Exception): logs.collect(self.base / 'x/../other', paired=paired)
        self.assertEqual(paired.opened, 0)
    def test_reparse_output_parent_refused(self):
        link = self.base / 'link'
        try: link.symlink_to(self.base, target_is_directory=True)
        except OSError: self.skipTest('host cannot create symlinks')
        paired = Paired(Terminal())
        with self.assertRaises(Exception): logs.collect(link / 'other', paired=paired)
        self.assertEqual(paired.opened, 0)
    def test_windows_reparse_attribute_refused_without_privileged_symlink(self):
        parent = self.base / 'reparse'; parent.mkdir()
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            if path == parent:
                return types.SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        paired = Paired(Terminal())
        with mock.patch.object(Path, 'lstat', lstat):
            with self.assertRaises(Exception): logs.collect(parent / 'other', paired=paired)
        self.assertEqual(paired.opened, 0)
        self.assertFalse((parent / 'other').exists())
    def test_old_native_version_stops_before_listing(self):
        terminal = Terminal(); terminal.version = '02.09'
        report = self.fails(terminal)
        self.assertIn('02.10', report['reason'])
        self.assertEqual(terminal.commands, [])
    def test_casefold_collision_and_unsafe_names_before_get(self):
        for tree in ({'a.log': b'a', 'A.log': b'b'}, {'../save': b'x'}, {'CON.log': b'x'},
                     {'COM1 .log': b'x'}, {'.hidden': b'x'}, {'bad.': b'x'}):
            with self.subTest(tree=list(tree)):
                self.out = self.base / ('case' + str(len(list(self.base.iterdir()))))
                terminal = Terminal(tree); self.fails(terminal)
                self.assertFalse(any(c.startswith('get ') for c in terminal.commands))
    def test_error_or_partial_listing_never_accepted(self):
        for rows in ([row('fps.log', b'a'), b'ERR directory limit; use a narrower path'], [b'-rw-r--r-- 7'],
                     [b'ERR access denied'], [b'lrwxrwxrwx            1 2026-11-24 19:30 link'],
                     [b'-rw-r--r--            1 2026-99-24 19:30 x.log'], [b'\x1b[H']):
            with self.subTest(rows=rows):
                self.out = self.base / ('row' + str(len(list(self.base.iterdir()))))
                terminal = Terminal(); terminal.bad_rows = rows; self.fails(terminal)
                self.assertFalse(any(c.startswith('get ') for c in terminal.commands))
    def test_listing_byte_and_count_bounds(self):
        for count in (513, 100):
            self.out = self.base / ('bound' + str(count))
            terminal = Terminal()
            terminal.bad_rows = [row(('x' * 90) + f'{n:03d}.log', b'') for n in range(count)]
            self.fails(terminal)
            self.assertFalse(any(c.startswith('get ') for c in terminal.commands))
    def test_configured_file_total_entry_and_depth_limits(self):
        for limits in (logs.Limits(max_file_bytes=2), logs.Limits(max_total_bytes=2),
                       logs.Limits(max_entries=1), logs.Limits(max_depth=0)):
            self.out = self.base / ('lim' + str(len(list(self.base.iterdir()))))
            terminal = Terminal(); self.fails(terminal, limits=limits)
            self.assertFalse(any(c.startswith('get ') for c in terminal.commands))
    def test_partial_transfer_keeps_confirmed_receipts_no_retry_or_delete(self):
        terminal = Terminal({'a.log': b'first', 'z.log': b'later'})
        terminal.fail_remote = logs.REMOTE_ROOT + '/z.log'
        report = self.fails(terminal)
        self.assertEqual(report['files_planned'], 2)
        self.assertEqual(len(report['receipts']), 1)
        self.assertEqual(report['unconfirmed'], terminal.fail_remote)
        self.assertEqual((self.out / 'Logs/a.log').read_bytes(), b'first')
        self.assertFalse((self.out / 'Logs/z.log').exists())
        self.assertEqual(sum(c == 'get ' + logs.wb.quoted_path(terminal.fail_remote) for c in terminal.commands), 1)
    def test_wrong_receipt_or_local_hash_not_confirmed(self):
        terminal = Terminal({'a.log': b'first'}); terminal.wrong_receipt = True
        report = self.fails(terminal)
        self.assertEqual(report['receipts'], [])
        self.assertEqual((self.out / 'Logs/a.log').read_bytes(), b'first')
    def test_destination_appearing_mid_collection_not_overwritten(self):
        terminal = Terminal({'a.log': b'first'})
        def occupy(local): local.write_bytes(b'somebody else')
        terminal.before_pull = occupy
        report = self.fails(terminal)
        self.assertEqual((self.out / 'Logs/a.log').read_bytes(), b'somebody else')
        self.assertEqual(report['receipts'], [])
    def test_remote_metadata_changes_after_download_incomplete(self):
        terminal = Terminal({'a.log': b'first'}); terminal.change_listing = True
        report = self.fails(terminal)
        self.assertEqual(len(report['receipts']), 1)
        self.assertIn('directory changed', report['reason'])
    def test_same_run_transport_identity_required_at_end(self):
        terminal = Terminal({'a.log': b'first'}); terminal.bad_identity = True
        report = self.fails(terminal)
        self.assertIn('run/transport', report['reason'])
    def test_invalid_limits_fail_before_filesystem_or_ssh(self):
        for limits in (logs.Limits(timeout=float('inf')), logs.Limits(timeout=-1), logs.Limits(max_entries=0),
                       logs.Limits(max_depth=13), logs.Limits(max_file_bytes=-1), logs.Limits(max_total_bytes=-1)):
            paired = Paired(Terminal())
            with self.assertRaises(logs.Problem): logs.collect(self.out, paired=paired, limits=limits)
            self.assertEqual(paired.opened, 0)
            self.assertFalse(self.out.exists())
    def test_failure_report_does_not_stringify_lowerlevel_secrets(self):
        @contextlib.contextmanager
        def refused(): raise RuntimeError('private key material must never be reported'); yield
        with self.assertRaises(logs.PartialCollection): logs.collect(self.out, paired=refused)
        raw = (self.out / logs.REPORT).read_text()
        self.assertNotIn('private key material', raw)
        self.assertEqual(json.loads(raw)['reason'], 'RuntimeError')
    def test_checkpoint_write_failure_retains_prior_report_and_partial_state(self):
        terminal = Terminal({'a.log': b'first'})
        replace = logs.os.replace
        calls = []
        def fail_later(source, target):
            calls.append((source, target))
            if len(calls) > 1: raise OSError('simulated full disk')
            return replace(source, target)
        with mock.patch.object(logs.os, 'replace', fail_later):
            with self.assertRaises(logs.PartialCollection) as caught:
                logs.collect(self.out, paired=Paired(terminal))
        self.assertFalse(caught.exception.report['complete'])
        self.assertFalse(caught.exception.report['report_saved'])
        self.assertEqual(caught.exception.report['report_write_error'], 'OSError')
        prior = json.loads((self.out / logs.REPORT).read_bytes())
        self.assertFalse(prior['complete'])
        self.assertEqual(prior['receipts'], [])
        self.assertFalse(list(self.out.glob('.report-*.partial')))
    def test_fixed_namespace_and_name_restrictions(self):
        for parent, name in [('ux0:/data/OTHER0001/Logs', 'a.log'), (logs.REMOTE_ROOT, '..'),
                             (logs.REMOTE_ROOT, 'a/b'), (logs.REMOTE_ROOT, 'bad\\file')]:
            with self.assertRaises(logs.Problem): logs.remote_child(parent, name)
        self.assertEqual(logs.remote_child(logs.REMOTE_ROOT, 'two words.log'), logs.REMOTE_ROOT + '/two words.log')


if __name__ == '__main__':
    unittest.main(verbosity=2)
