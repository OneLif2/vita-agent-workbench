"""Offline, owner-maintained Vita App preflight. No transport or deployment code."""
from __future__ import annotations

import argparse
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

REGISTRY = Path(__file__).resolve().with_name("apps.txt")
TITLE = re.compile(r"[A-Z]{4}[0-9]{5}")
VERSION = re.compile(r"[0-9]{2}\.[0-9]{2}")
SHA = re.compile(r"[0-9a-f]{64}")
CASE = re.compile(r"[a-z][a-z0-9-]{0,31}")
MAX_VPK = 32 * 1024 * 1024  # scope of this first, small homebrew slice
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


def read_identity(data: bytes) -> tuple[str, str]:
    # Invoked only AFTER a whole-VPK hash matches a local registry entry.
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        files = z.infolist()
        names = set()
        for info in files:
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


def approve(package: Path, case: str | None = None, *, registry: Path | None = None):
    """Return approval and exactly the bytes checked. Registry override is for fixture injection, not CLI."""
    try:
        demand(case is None or CASE.fullmatch(case), "invalid-case")
        rows = load_registry(REGISTRY if registry is None else registry)
        raw = local_bytes(package, MAX_VPK)
        digest = hashlib.sha256(raw).hexdigest()
        demand(digest in rows, "sha256-not-approved")
        entry = rows[digest]
        title, version = read_identity(raw)
        demand((title, version) == (entry.title, entry.version), "package-identity-mismatch")
        if case is not None:
            demand(case in entry.cases, "case-not-approved")
        return {"status": "APPROVED_LOCAL_PLAN", "title_id": title, "app_ver": version,
                "bytes": len(raw), "sha256": digest, "case": case,
                "install_only": not bool(entry.cases)}, raw
    except Denied:
        raise
    except (OSError, KeyError, ValueError, RuntimeError, NotImplementedError,
            struct.error, zipfile.BadZipFile, EOFError, zlib.error) as exc:
        raise Denied("unreadable-or-malformed-input") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vpk", type=Path)
    parser.add_argument("--case", help="also check a test case (omit for install-only)")
    args = parser.parse_args(argv)
    try:
        verdict, _ = approve(args.vpk, args.case)
    except Denied as err:
        print(json.dumps({"status": "DENIED", "reason": str(err)}))
        return 2
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
