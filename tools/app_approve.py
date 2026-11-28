"""Owner-signed runtime approval for one exact game artifact.

Replaces the "rebuild a core for every game build" loop. The device verifies the
signature with its enrolled release key before writing anything, so this tool by
itself can never approve a package the owner did not sign.

  python -B tools/app_approve.py --vpk PATH --remote ux0:/VITA-POC/NAME.vpk [--dry-run]

Prints the exact canonical message it signs, so the approval is auditable.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(R/'tools'))
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def load_sfo(path):
    from wbctl import parse_sfo
    import zipfile, io
    blob = Path(path).read_bytes()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        sfo = z.read('sce_sys/param.sfo')
    parsed = parse_sfo(sfo)
    return blob, parsed.get('TITLE_ID', ''), parsed.get('APP_VER', '')


def message(title, ver, size, sha):
    return (f'WB-APP-APPROVE-v1\nTITLE {title}\nVER {ver}\nBYTES {size}\nSHA256 {sha}\n').encode('ascii')


def main():
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument('--vpk', type=Path, required=True)
    ap.add_argument('--remote', required=True, help='device path under ux0:/VITA-POC/')
    ap.add_argument('--dry-run', action='store_true', help='sign and print only; send nothing')
    a = ap.parse_args()

    if not a.remote.startswith('ux0:/VITA-POC/'):
        raise SystemExit('the device package must live under ux0:/VITA-POC/')
    blob, title, ver = load_sfo(a.vpk)
    sha = hashlib.sha256(blob).hexdigest()
    msg = message(title, ver, len(blob), sha)
    print('title   :', title)
    print('version :', ver)
    print('bytes   :', len(blob))
    print('sha256  :', sha)
    print('message :')
    for line in msg.decode().splitlines():
        print('   ', line)

    from standing_key_dpapi import load
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils
    key_path = Path(os.environ['LOCALAPPDATA']).resolve(strict=True)/'VitaWorkbench/trust/standing-r1/release-p256.dpapi'
    key = load(key_path)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SystemExit('protected signing key is not P-256')
    r, s = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    s = min(s, P256_N - s)
    if not (0 < r < P256_N and 0 < s <= P256_N//2):
        raise SystemExit('noncanonical P-256 signature')
    print('signature: r=%064x s=%064x' % (r, s))

    if a.dry_run:
        print('DRY_RUN: nothing sent')
        return 0

    import wbterm as w
    import stage_review as flow
    PIN = 'HOST_SHA256'
    command = f'app approve {a.remote} {r:064x} {s:064x}'
    with w.paired_terminal() as t:
        t.ch.settimeout(300)
        assert t.host_pin == PIN, 'pin changed'
        rows = flow.reply(t, command)
        if len(rows) > 1:
            rows = [x for x in rows if x.strip()]
        print('device  :', rows, flush=True)
        ok = any(x.startswith('OK app-approve') for x in rows)
        listing = flow.reply(t, 'app list')
        mine = [x for x in listing if title in x]
        print('app list:', mine, flush=True)
        approved = any('source=owner-signed' in x and sha in x for x in mine)
    if not (ok and approved):
        return 3
    print('APPROVED_AT_RUNTIME install-only title=%s ver=%s sha256=%s' % (title, ver, sha))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
