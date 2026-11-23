#!/usr/bin/env python3
"""Compile the 5090 owner's fixed, local apps.txt into a private C build include."""
import argparse
import hashlib
import os
from pathlib import Path
import tempfile

from app_registry import Denied, REGISTRY, load_registry


def emit(output, catalog):
    # No output if the entire catalog does not validate. Use the exact same parser as wbctl.
    rows = sorted(load_registry(catalog).values(), key=lambda e:(e.title, e.version, e.sha256))
    policy = "".join(f"{e.title} {e.version} {e.sha256} {','.join(sorted(e.cases)) or '-'}\n" for e in rows)
    digest = hashlib.sha256(policy.encode("ascii")).hexdigest()
    # Allowed characters have already been validated, including case delimiters.
    source = f"/* Generated from validated apps.txt; canonical SHA-256: {digest}. */\n"
    for e in rows:
        source += '    {"%s", "%s", "%s", "%s"},\n' % (e.title, e.version, e.sha256, ",".join(sorted(e.cases)))
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".registry-", delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(source.encode("ascii"))
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            f.close()
            tmp.unlink()
            raise
    try:
        os.replace(tmp, path)
    finally:
        if tmp.exists(): tmp.unlink()
    return len(rows), digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="build-only output include; input is always adjacent apps.txt")
    args = parser.parse_args()
    try: count, sha = emit(args.output, REGISTRY)
    except (OSError, ValueError, Denied) as exc: parser.exit(2, "Registry generation refused: %s\n" % exc)
    print(f"App registry: {count} approved artifact(s); canonical SHA-256 {sha}")
