"""Read one approved game's Logs tree through the paired Workbench PTY only.

  python -B tools/game_logs.py --out D:\\VitaEvidence\\game-logs-new
  python -B tools/game_logs.py --title RJGP52237 --out D:\\VitaEvidence\\perflab-logs-new

RJGM52237 requires Workbench 02.10; RJGP52237 requires 02.11 or newer.
Never installs, writes/deletes on the Vita,
changes permissions, uses SSH exec/SFTP/FTP, or sends game/controller input.
The output directory must be new. A failed collection is retained with a
partial report; no automatic retry or claim of an atomic remote snapshot.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time

import wbterm as wb

REMOTE_ROOT = 'ux0:/data/RJGM52237/Logs'
TITLE = 'RJGM52237'
LOG_TARGETS = {
    'RJGM52237': (REMOTE_ROOT, '02.10'),
    'RJGP52237': ('ux0:/data/RJGP52237/Logs', '02.11'),
}
REPORT = 'report.json'
LIST_BYTES = 8192 + 512  # Native LF budget plus the PTY's added CR bytes.
LIST_ROWS = 512
UINT32_MAX = (1 << 32) - 1
HEX = re.compile(r'[0-9a-f]{64}')
ROW = re.compile(r'([d-](?:[r-][w-][x-]){3}) +(-|0|[1-9][0-9]{0,19}) +(\?|[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}) +(.+)')
NAME = re.compile(r'[A-Za-z0-9_.() -]{1,100}')
RESERVED = re.compile(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', re.I)


class Problem(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Problem(reason)


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_entries: int = 1024
    max_depth: int = 12
    timeout: float = 1800

    def validate(self):
        need(type(self.max_file_bytes) is int and 0 <= self.max_file_bytes <= UINT32_MAX, 'invalid file byte limit')
        need(type(self.max_total_bytes) is int and 0 <= self.max_total_bytes <= (1 << 40), 'invalid total byte limit')
        need(type(self.max_entries) is int and 1 <= self.max_entries <= 65536, 'invalid entry limit')
        need(type(self.max_depth) is int and 0 <= self.max_depth <= 12, 'invalid depth limit')
        need(isinstance(self.timeout, (int, float)) and math.isfinite(self.timeout) and 0 < self.timeout <= 21600,
             'invalid finite timeout')


@dataclass(frozen=True)
class Entry:
    name: str
    directory: bool
    size: int | None
    modified: str | None


def valid_name(name):
    return (isinstance(name, str) and NAME.fullmatch(name) is not None and name[0] not in '. '
            and name[-1] not in '. ' and not RESERVED.fullmatch(name)
            and not RESERVED.fullmatch(name.split('.', 1)[0].rstrip(' ')))


def parse_row(raw):
    try:
        text = raw.decode('ascii')
    except (UnicodeDecodeError, AttributeError) as exc:
        raise Problem('non-ASCII listing row') from exc
    need(all(32 <= ord(c) < 127 for c in text), 'listing control character')
    match = ROW.fullmatch(text)
    need(match is not None, 'malformed or error listing row')
    mode, size, modified, leaf = match.groups()
    directory = mode[0] == 'd'
    need(leaf.endswith('/') == directory, 'listing file type/suffix mismatch')
    name = leaf[:-1] if directory else leaf
    need(valid_name(name), 'unsafe or nonportable log name')
    need((size == '-') == directory, 'listing file type/size mismatch')
    if modified != '?':
        try:
            stamp = dt.datetime.strptime(modified, '%Y-%m-%d %H:%M')
        except ValueError as exc:
            raise Problem('invalid native timestamp') from exc
        need(1980 <= stamp.year <= 9999, 'invalid native timestamp year')
    return Entry(name, directory, None if directory else int(size), None if modified == '?' else modified)


def target_for(title):
    need(isinstance(title, str) and title in LOG_TARGETS, 'unsupported log title')
    return LOG_TARGETS[title]


def checked_root(root):
    need(root in tuple(value[0] for value in LOG_TARGETS.values()), 'unsupported log root')
    return root


def remote_child(parent, name, *, root=REMOTE_ROOT):
    checked_root(root)
    need(parent == root or parent.startswith(root + '/'), 'outside selected game Logs namespace')
    need(valid_name(name), 'unsafe log path segment')
    result = parent + '/' + name
    wb.quoted_path(result)  # Same canonical path/length policy as actual GET.
    return result


def listing(terminal, remote, audit=None, *, root=REMOTE_ROOT):
    checked_root(root)
    need(remote == root or remote.startswith(root + '/'), 'outside selected game Logs namespace')
    command = 'ls -l ' + wb.quoted_path(remote)
    event = dict(command=command, stdout_lines=[], complete=False)
    if audit is not None:
        audit.append(event)
    terminal.command(command)
    entries = []
    total = 0
    seen = set()
    rp = getattr(terminal, 'root_prompt', wb.ROOT_PROMPT)
    while True:
        while not terminal.buf:
            terminal._more()
        while len(terminal.buf) < len(rp) and rp.startswith(terminal.buf):
            terminal._more()
        if terminal.buf.startswith(rp):
            terminal.exact(rp)
            event['complete'] = True
            return tuple(sorted(entries, key=lambda e: (e.name.casefold(), e.name)))
        raw = terminal.line()
        event['stdout_lines'].append(raw.decode('ascii', 'backslashreplace'))
        total += len(raw) + 2
        need(total <= LIST_BYTES and len(entries) < LIST_ROWS, 'listing exceeds native bound')
        entry = parse_row(raw)  # ERR and incomplete rows are never an empty list.
        key = entry.name.casefold()
        need(key not in seen, 'case-insensitive directory collision')
        seen.add(key)
        remote_child(remote, entry.name, root=root)
        entries.append(entry)


def output_path(raw):
    name = str(raw)
    need(not name.startswith(('//', '\\\\')) and '://' not in name, 'output must be on a local drive')
    path = wb.wb_tree.source_path(Path(raw).expanduser())
    if os.name == 'nt':
        import ctypes
        need(ctypes.windll.kernel32.GetDriveTypeW(path.anchor) in (2, 3, 6), 'output must be on a local drive')
    need(not os.path.lexists(path), 'output already exists; use a fresh directory')
    return path


def identity_of(path):
    st = wb.wb_tree.unlinked(path)
    need(stat.S_ISDIR(st.st_mode), 'expected local directory')
    return st.st_dev, st.st_ino


def collect(out, *, paired=wb.paired_terminal, limits=Limits(), title=TITLE):
    """Only the paired context and Terminal's existing read-only methods act remotely."""
    limits.validate()
    remote_root, required_version = target_for(title)
    out = output_path(out)
    out.mkdir()  # Exclusive, no merge. Existing targets are refused before SSH.
    root_id = identity_of(out)
    logs = out / 'Logs'
    logs.mkdir()
    report = dict(schema='wb.game-logs.v1', title=title, remote=remote_root, output=str(out),
                  complete=False, receipts=[], directories=[], bytes_confirmed=0,
                  limits=vars(limits), atomic_remote_snapshot=False, device_writes=False,
                  scope='entries exposed by Workbench read-only Logs projection, not every underlying filesystem entry',
                  excluded_by_native_policy='unsupported/hidden names, unsafe types or aliases are not exposed',
                  commands=[])
    report_id = None

    def safe(local):
        need(identity_of(out) == root_id, 'local output root replaced')
        candidate = wb.wb_tree.source_path(local)
        need(candidate == out or out in candidate.parents, 'local path escaped output')
        return candidate

    def save():
        nonlocal report_id
        safe(out)
        path = out / REPORT
        def report_unchanged():
            if not os.path.lexists(path):
                need(report_id is None, 'report checkpoint removed')
                return
            st = wb.wb_tree.unlinked(path)
            need(stat.S_ISREG(st.st_mode) and report_id == (st.st_dev, st.st_ino), 'report path appeared or replaced')
        report_unchanged()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=out, prefix='.report-', suffix='.partial', delete=False,
                                             mode='w', encoding='utf8', newline='\n') as stream:
                temporary = Path(stream.name)
                json.dump(report, stream, indent=2)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            safe(out)
            report_unchanged()
            # Windows/OneDrive file scanners can transiently hold a lock on report.json.
            for attempt in range(6):
                try:
                    os.replace(temporary, path)  # Same-volume checkpoint; retain the old report on failure.
                    break
                except PermissionError:
                    if os.name != 'nt' or attempt == 5:
                        raise
                    time.sleep(0.08)
            current = wb.wb_tree.unlinked(path)
            report_id = (current.st_dev, current.st_ino)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    try:
        save()
        with paired() as terminal:
            need(terminal.version >= required_version, f'Workbench {required_version} or newer is required for {title}')
            terminal.deadline = time.monotonic() + limits.timeout
            terminal.ch.settimeout(min(30, limits.timeout))
            first = terminal.check()
            need(first.get('channel') == 'one interactive PTY' and first.get('host_sha256') == terminal.host_pin
                 and first.get('transport_sha256') == terminal.transport_id and HEX.fullmatch(terminal.host_pin)
                 and HEX.fullmatch(terminal.transport_id), 'unverified PTY identity')
            report['identity'] = first
            plan = []
            snapshots = []
            bytes_planned = 0

            def walk(remote, rel, depth):
                nonlocal bytes_planned
                need(depth <= limits.max_depth, 'log tree exceeds depth limit')
                need(len(plan) < limits.max_entries, 'log tree exceeds entry limit')
                plan.append((remote, rel, True, None))
                entries = listing(terminal, remote, report['commands'], root=remote_root)
                snapshots.append((remote, entries))
                for entry in entries:
                    child = remote_child(remote, entry.name, root=remote_root)
                    child_rel = rel / entry.name
                    if entry.directory:
                        walk(child, child_rel, depth + 1)
                    else:
                        need(depth + 1 <= limits.max_depth and len(plan) < limits.max_entries, 'log tree exceeds limits')
                        need(entry.size <= limits.max_file_bytes, 'log file exceeds configured byte limit')
                        bytes_planned += entry.size
                        need(bytes_planned <= limits.max_total_bytes, 'logs exceed configured total byte limit')
                        plan.append((child, child_rel, False, entry.size))

            walk(remote_root, Path(), 0)
            report.update(entries_planned=len(plan), files_planned=sum(not p[2] for p in plan), bytes_planned=bytes_planned)
            save()
            for remote, rel, directory, size in plan:
                local = safe(logs / rel)
                report['unconfirmed'] = remote
                if directory:
                    if rel.parts:
                        local.mkdir()
                    identity_of(local)
                    report['directories'].append(dict(remote=remote, local=str(local)))
                else:
                    need(not os.path.lexists(local), 'local destination appeared; no overwrite')
                    event = dict(command='get ' + wb.quoted_path(remote), complete=False,
                                 protocol='TTY1 via existing verified Terminal.pull; contents not included')
                    report['commands'].append(event)
                    receipt = terminal.pull(remote, local, max_bytes=limits.max_file_bytes)
                    need(isinstance(receipt, dict) and receipt.get('action') == 'get' and receipt.get('remote') == remote
                         and receipt.get('local') == str(local.absolute()) and receipt.get('bytes') == size
                         and isinstance(receipt.get('sha256'), str) and HEX.fullmatch(receipt['sha256']), 'download receipt mismatch')
                    safe(local)
                    with wb.wb_tree.checked_open(local) as stream:
                        st = os.fstat(stream.fileno())
                        need(st.st_size == size, 'download differs from listed size')
                        digest = wb.wb_tree.file_digest(stream, size)
                    need(digest == receipt['sha256'], 'local download digest mismatch')
                    report['receipts'].append(receipt)
                    report['bytes_confirmed'] += size
                    event.update(complete=True, receipt=receipt)
                save()
            # Detect directory changes rather than silently calling a partial plan complete.
            for remote, original in snapshots:
                need(listing(terminal, remote, report['commands'], root=remote_root) == original, 'log directory changed during collection')
            need(terminal.check() == first, 'source run/transport changed during collection')
            report.pop('unconfirmed', None)
            report.update(complete=True, status='VERIFIED_FILES_AND_STABLE_LISTINGS',
                          files_verified=len(report['receipts']), report=str(out / REPORT))
            save()
    except (Exception, KeyboardInterrupt) as exc:
        report.update(status='INCOMPLETE_NO_AUTOMATIC_RETRY', reason=str(exc) if isinstance(exc, Problem) else type(exc).__name__)
        try:
            save()
        except Exception as persist:
            # Do not turn a started/partial collection into a false NOT_STARTED
            # response or destroy the previous atomic checkpoint on disk-full.
            report.update(report_saved=False, report_write_error=type(persist).__name__)
        raise PartialCollection(report) from exc
    return report


class PartialCollection(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__('incomplete log collection; retain receipts and use a new output directory for a later attempt')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--title', choices=tuple(LOG_TARGETS), default=TITLE,
                        help='fixed read-only Logs title (no arbitrary remote root)')
    parser.add_argument('--max-file-bytes', type=int, default=Limits.max_file_bytes)
    parser.add_argument('--max-total-bytes', type=int, default=Limits.max_total_bytes)
    parser.add_argument('--max-entries', type=int, default=Limits.max_entries)
    parser.add_argument('--max-depth', type=int, default=Limits.max_depth)
    parser.add_argument('--timeout', type=float, default=Limits.timeout)
    args = parser.parse_args(argv)
    try:
        report = collect(args.out, title=args.title, limits=Limits(args.max_file_bytes, args.max_total_bytes, args.max_entries, args.max_depth, args.timeout))
        print(json.dumps(report)); return 0
    except PartialCollection as exc:
        print(json.dumps(exc.report)); return 2
    except Exception as exc:
        print(json.dumps(dict(status='NOT_STARTED', reason=str(exc) if isinstance(exc, Problem) else type(exc).__name__))); return 2


if __name__ == '__main__':
    raise SystemExit(main())
