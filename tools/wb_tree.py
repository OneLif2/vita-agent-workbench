"""Bounded, no-merge send planning. No transport or SSH credentials in this module."""
from __future__ import annotations
import contextlib, os, stat
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

ROOT = 'ux0:/VITA-POC'
MAX_ENTRIES, MAX_DEPTH, MAX_BYTES = 256, 12, 192 * 1024 * 1024

class TreeError(ValueError): pass

def insist(ok, reason):
    if not ok: raise TreeError(reason)

def signature(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns

def unlinked(path):
    st=path.lstat()
    insist(not stat.S_ISLNK(st.st_mode) and not (
        getattr(st,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400)),
        f'links and reparse points are not followed: {path}')
    return st

def source_path(raw):
    p=Path(raw)
    insist('..' not in p.parts,'parent traversal is not a source selector')
    p=p.absolute()
    for q in reversed(p.parents):
        insist(stat.S_ISDIR(unlinked(q).st_mode),f'non-directory ancestor: {q}')
    return p

@contextlib.contextmanager
def checked_open(local, sig=None):
    path=source_path(local);before=unlinked(path)
    insist(stat.S_ISREG(before.st_mode),'expected a regular local file')
    sig=signature(before) if sig is None else sig
    insist(signature(before)==sig,'source changed since preflight')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as file:
        insist(signature(os.fstat(file.fileno()))==sig,'source changed while opening')
        yield file

@dataclass(frozen=True)
class Entry:
    local: Path
    remote: str
    directory: bool
    sig: tuple

@dataclass(frozen=True)
class Plan:
    dest: str
    roots: tuple
    entries: tuple
    total: int

def plan(sources, dest, recursive, quoted):
    # Require an existing remote parent. Never create a tree up to a mistyped root.
    quoted(dest)
    insist(dest==ROOT or dest.startswith(ROOT+'/'),'send is limited to '+ROOT)
    insist(len(sources)>0,'no sources')
    entries=[]; roots=[]; seen=set(); dirs=set(); total=0
    def walk(local, remote):
        nonlocal total
        quoted(remote)
        insist(len(remote[len(ROOT)+1:].split('/'))<=MAX_DEPTH,'remote depth limit')
        key=remote.casefold()
        insist(key not in seen,'case-insensitive destination collision: '+remote)
        insist(len(entries)<MAX_ENTRIES,'batch entry limit exceeded')
        seen.add(key); st=unlinked(local); directory=stat.S_ISDIR(st.st_mode)
        insist(directory or stat.S_ISREG(st.st_mode),'special source refused: '+str(local))
        entries.append(Entry(local,remote,directory,signature(st)))
        if not directory:
            total+=st.st_size
            insist(0<=st.st_size<=MAX_BYTES and total<=MAX_BYTES,'batch byte limit exceeded')
            return
        insist(recursive,'directories require --recursive (-r)')
        identity=(st.st_dev,st.st_ino)
        insist(identity not in dirs,'directory already visited (alias or overlapping roots)')
        dirs.add(identity)
        with os.scandir(local) as stream:
            names=[entry.name for entry in islice(stream,MAX_ENTRIES-len(entries)+1)]
        insist(len(names)<=MAX_ENTRIES-len(entries),'batch entry limit exceeded')
        for name in sorted(names,key=lambda x:(x.casefold(),x)):
            walk(local/name,remote+'/'+name)
        insist(signature(unlinked(local))==signature(st),'directory changed during enumeration')
    for raw in sources:
        path=source_path(raw)
        insist(bool(path.name),'do not send a filesystem root')
        remote=dest+'/'+path.name
        roots.append(remote); walk(path,remote)
    return Plan(dest,tuple(roots),tuple(entries),total)

class PartialSend(RuntimeError):
    def __init__(self, report):
        self.report=report
        super().__init__('batch interrupted: consult confirmed receipts before retrying')

def send(t, p, quoted):
    insist(t.version >= '01.66','multi-file send requires Workbench 01.66 or newer')
    def probe(path):return t.one('tree-stat '+quoted(path))
    insist(probe(p.dest)=='TTY1 OK DIR','remote parent is not an existing directory')
    # A new top-level root cannot contain pre-existing children. Never merge
    # even into an empty existing folder. Server rechecks every target on use.
    for root in p.roots:
        insist(probe(root)=='TTY1 OK ABSENT','destination exists or unavailable: '+root)
    for item in p.entries:
        insist(signature(unlinked(source_path(item.local)))==item.sig,'source changed after planning')
    done=[]
    report=dict(action='send',remote=p.dest,receipts=done,files_planned=sum(not x.directory for x in p.entries),
                entries_planned=len(p.entries),bytes_planned=p.total,host_sha256=t.host_pin,
                transport_sha256=t.transport_id)
    for item in p.entries:
        try:
            if item.directory:
                insist(signature(unlinked(source_path(item.local)))==item.sig,'directory changed after planning')
                insist(t.one('tree-mkdir '+quoted(item.remote))=='TTY1 OK MKDIR','unexpected mkdir receipt')
                done.append(dict(action='mkdir',remote=item.remote))
            else:
                done.append(t.push(item.local,item.remote,snapshot=item.sig))
        except (Exception, KeyboardInterrupt) as exc:
            # Including disconnect after END / mkdir. Never undo someone else's
            # data or assert that a missing receipt means no file was published.
            report.update(complete=False,unconfirmed=item.remote,reason=f'{type(exc).__name__}: {str(exc)[:220]}')
            raise PartialSend(report) from exc
    report['complete']=True
    return report
