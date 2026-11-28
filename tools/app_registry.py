"""Offline, owner-maintained Vita App preflight. No transport or deployment code."""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile
import zlib
import wb_tree

REGISTRY = Path(__file__).resolve().with_name("apps.txt")
TITLE = re.compile(r"[A-Z]{4}[0-9]{5}")
VERSION = re.compile(r"[0-9]{2}\.[0-9]{2}")
SHA = re.compile(r"[0-9a-f]{64}")
CASE = re.compile(r"[a-z][a-z0-9-]{0,31}")
# Ordinary ZIP32 (ZIP64 sentinel is not an ordinary 32-bit size/offset).
MAX_VPK = (1 << 32) - 2
CORE_TITLES = {"INAP00018", "INAP00019"}


def allowed_registry_title(title):
    # Reserve earlier project / Workbench titles and the NP/PC catalog namespaces.
    # The catalog is owner-authored data, not a means to approve the core or a system title.
    return (TITLE.fullmatch(title) is not None and title not in CORE_TITLES
            and not title.startswith(("NP", "PC"))
            and (not title.startswith("INAP") or int(title[4:]) >= 20))


class Denied(ValueError):
    pass


def demand(ok, code):
    if not ok:
        raise Denied(code)


@dataclass(frozen=True)
class Entry:
    title: str
    version: str
    sha256: str
    cases: tuple[str, ...]


def local_bytes(path: Path, limit: int) -> bytes:
    name = str(path)
    demand(not name.startswith(("//", "\\\\")) and "://" not in name,
           "nonlocal-path")
    if os.name == "nt":
        import ctypes
        drive = path.absolute().anchor
        demand(drive and not drive.startswith("\\\\") and
               ctypes.windll.kernel32.GetDriveTypeW(drive) in (2, 3, 6),
               "nonlocal-drive")
    demand(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "not-regular-file")
    with path.open("rb") as f:
        size = os.fstat(f.fileno()).st_size
        demand(0 < size <= limit, "size-out-of-bounds")
        data = f.read(size + 1)
    demand(len(data) == size, "input-changed-or-short")
    return data


def load_registry(path: Path) -> dict[str, Entry]:
    rows = {}
    identities = set()
    data = local_bytes(path, 16384)
    demand(all(c in (9,10,13) or 32 <= c <= 126 for c in data), "invalid-registry-ascii")
    for line in data.decode("ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        demand(len(fields) == 4 and len(rows) < 64, "invalid-registry-row")
        title, version, digest, case_list = fields
        cases = () if case_list == "-" else tuple(case_list.split(","))
        demand(allowed_registry_title(title) and
               VERSION.fullmatch(version) and SHA.fullmatch(digest), "invalid-registry-identity")
        demand(len(cases) <= 32 and len(set(cases)) == len(cases) and
               all(CASE.fullmatch(c) for c in cases), "invalid-registry-cases")
        demand((title, version) not in identities and digest not in rows,
               "ambiguous-registry")
        rows[digest] = Entry(title, version, digest, cases)
        identities.add((title, version))
    demand(rows, "empty-registry")
    return rows


def read_identity(data) -> tuple[str, str]:
    # Invoked only AFTER a whole-VPK hash matches a local registry entry.
    with zipfile.ZipFile(io.BytesIO(data) if isinstance(data, bytes) else data) as z:
        files = z.infolist()
        demand(len(files) < 65535 and z.start_dir < 0xffffffff, "zip64-not-supported")
        names = set()
        for info in files:
            demand(info.extract_version < 45 and
                   max(info.file_size, info.compress_size, info.header_offset) < 0xffffffff,
                   "zip64-not-supported")
            # A forced ZIP64 member may have small decoded values. It is still
            # outside the native installer's ordinary ZIP32 contract.
            extra=info.extra
            while extra:
                demand(len(extra)>=4, "malformed-zip-extra")
                tag,n=struct.unpack_from('<HH',extra)
                demand(n<=len(extra)-4, "malformed-zip-extra")
                demand(tag!=1, "zip64-not-supported")
                extra=extra[4+n:]
            name = info.filename.casefold()
            demand(name not in names, "duplicate-zip-member")
            names.add(name)
        demand({"eboot.bin", "sce_sys/param.sfo"} <= {i.filename for i in files},
               "missing-vpk-members")
        info = z.getinfo("sce_sys/param.sfo")
        demand(not info.flag_bits & 1 and 20 <= info.file_size <= 65536, "invalid-sfo-size")
        with z.open(info) as f:
            s = f.read(65537)
        demand(len(s) == info.file_size, "invalid-sfo-size")
    magic, ver, keys, values, count = struct.unpack_from("<4s4I", s)
    demand(magic == b"\x00PSF" and ver == 0x101 and 1 <= count <= 256 and
           20 + 16 * count <= keys < values <= len(s), "invalid-sfo-header")
    seen = set()
    identity = {}
    for i in range(count):
        ko, fmt, n, cap, off = struct.unpack_from("<HHIII", s, 20 + 16 * i)
        end = s.find(b"\0", keys + ko, values)
        demand(keys + ko < end < values and n <= cap and values + off + cap <= len(s),
               "invalid-sfo-entry")
        key = s[keys + ko:end].decode("ascii")
        demand(key not in seen, "duplicate-sfo-key")
        seen.add(key)
        if key in ("TITLE_ID", "APP_VER"):
            val = s[values + off:values + off + n]
            demand(fmt == 0x204 and val.endswith(b"\0") and b"\0" not in val[:-1],
                   "invalid-sfo-string")
            identity[key] = val[:-1].decode("ascii")
    demand(set(identity) == {"TITLE_ID", "APP_VER"}, "missing-sfo-identity")
    return identity["TITLE_ID"], identity["APP_VER"]


@contextlib.contextmanager
def approve_file(package: Path, case: str | None = None, *, registry: Path | None = None):
    """Approve a private disk snapshot; registry override is fixture-only, not CLI."""
    with contextlib.ExitStack() as stack:
        try:
            demand(case is None or CASE.fullmatch(case), "invalid-case")
            rows = load_registry(REGISTRY if registry is None else registry)
            # Preserve the local-drive guard without reading the package wholesale.
            name=str(package)
            demand(not name.startswith(("//", "\\\\")) and "://" not in name, "nonlocal-path")
            if os.name == "nt":
                import ctypes
                drive=package.absolute().anchor
                demand(drive and not drive.startswith("\\\\") and
                       ctypes.windll.kernel32.GetDriveTypeW(drive) in (2,3,6), "nonlocal-drive")
            source=stack.enter_context(wb_tree.file_snapshot(package, MAX_VPK))
            digest=source.sha256
            demand(digest in rows, "sha256-not-approved")
            entry = rows[digest]
            with wb_tree.checked_open(source.path, source.sig) as file:
                title, version = read_identity(file)
            demand((title, version) == (entry.title, entry.version), "package-identity-mismatch")
            if case is not None:
                demand(case in entry.cases, "case-not-approved")
            facts={"status": "APPROVED_LOCAL_PLAN", "title_id": title, "app_ver": version,
                   "bytes": source.size, "sha256": digest, "case": case,
                   "install_only": not bool(entry.cases)}
        except Denied:
            raise
        except (OSError, KeyError, ValueError, RuntimeError, NotImplementedError,
                struct.error, zipfile.BadZipFile, EOFError, zlib.error) as exc:
            raise Denied("unreadable-or-malformed-input") from exc
        yield facts, source


def approve(package: Path, case: str | None = None, *, registry: Path | None = None):
    """Legacy bytes API for frozen small-package consumers; CLI uses approve_file."""
    with approve_file(package, case, registry=registry) as (facts, source):
        with wb_tree.checked_open(source.path, source.sig) as file:
            raw=file.read(source.size+1)
        demand(len(raw)==source.size and hashlib.sha256(raw).hexdigest()==source.sha256,
               "input-changed-or-short")
        return facts, raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vpk", type=Path)
    parser.add_argument("--case", help="also check a test case (omit for install-only)")
    args = parser.parse_args(argv)
    try:
        with approve_file(args.vpk, args.case) as (verdict, _):
            pass
    except Denied as err:
        print(json.dumps({"status": "DENIED", "reason": str(err)}))
        return 2
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
