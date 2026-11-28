"""Offline recipe for ONE game delta; authenticated release archives, no Vita or signer.

By default validate against the checked-in header. --emit creates it once.
Use --manifest for the exact canonical bytes hashed into WB_PATCH_RECIPE_SHA.
This is a release-authoring tool; client machines don't need the VPKs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ITER = ROOT.parent / "iterations"
BASE = ITER / "game-round95-full-0109-20261127"
PREV12 = ITER / "game-0112-touch-release"
PREV13 = ITER / "game-0113-touch-release"
TARGET = ITER / "game-0116-touch-release"
HEADER = ROOT / "source" / "wb_app_patch_recipe.h"
TITLE, VER = "RJGM52237", "01.16"
PACKS = (
    ("01.09", BASE / "packages/RJGM52237-01.09-100pct-gpu.vpk", BASE / "VPK-PROOF.json",
     519595844, "167bb7f94fbaa20f0d849b2b4f2becc258be2f4ba1ccf52b63f46d075f044f3f"),
    ("01.10", BASE / "packages/RJGM52237-01.10-100pct-gpu.vpk", BASE / "VPK-0110-PROOF.json",
     519598256, "856ef0af0fdb9c67525cad091e76b5abc3cdd0a9dff50f452413abadf4f3fb02"),
    ("01.12", PREV12 / "RJGM52237-01.12-touch.vpk", PREV12 / "PACKAGE-RECEIPT.json",
     519640713, "e496f4692a5f7d8fea70d96e6a8d5257674116b9ac674d67daf9f0997ef3d596"),
    ("01.13", PREV13 / "RJGM52237-01.13-touch.vpk", PREV13 / "PACKAGE-RECEIPT.json",
     519641543, "b11430c1c04af32d0f4911f33d63e3519fc59ceb3513517e8018e7e130b1c357"),
    (VER, TARGET / "RJGM52237-01.16-touch.vpk", TARGET / "PACKAGE-RECEIPT.json",
     519643946, "e3d9e38441e1239eb9eb43df6ab3ae420d0afa083bcffe9d5cbe0ec4e1fdf6ee"),
)
EBOOT15_PROOF = BASE / "EBOOT-0115-PROOF.json"
EBOOT15_PATH = BASE / "build_0115/eboot.bin"
EBOOT15_BYTES = 2943848
EBOOT15_SHA = "3c3717f15ee53fb2d3bf1e942e789bf39e5cee5ff17969b7aea68777c63e53ed"

NAMES = (
    "eboot.bin", "sce_sys/param.sfo", "strings.dat", "media.rja", "audio.nsa", "font.ttc",
    "sce_sys/icon0.png", "sce_sys/livearea/contents/bg.png", "sce_sys/livearea/contents/startup.png",
    "sce_sys/livearea/contents/template.xml", "build-manifest.json",
)
EBOOT, SFO, MANIFEST = NAMES[0], NAMES[1], NAMES[-1]
META = (SFO, MANIFEST)
BOOT_SHA = "db8dcb3fe45b069e2bc567e41e52e6f8e79e1c2fbeb8bc86da08c0f540c01597"
BOOT_BYTES = 2944023


def must(test, why):
    if not test:
        raise ValueError(why)


def hash_bytes(b):
    return hashlib.sha256(b).hexdigest()


def filehash(f):
    h = hashlib.sha256()
    while part := f.read(1024 * 1024):
        h.update(part)
    return h.hexdigest()


def sfo_identity(b):
    must(b.startswith(b"\0PSF"), "SFO signature")
    _, keys, vals, n = struct.unpack_from("<4I", b, 4)
    must(20 + n * 16 <= keys <= vals <= len(b), "SFO tables")
    out = {}
    for i in range(n):
        ko, fmt, size, cap, vo = struct.unpack_from("<HHIII", b, 20 + 16 * i)
        name = b[keys + ko : b.index(0, keys + ko, vals)].decode("ascii")
        must(name not in out and vals + vo + cap <= len(b) and size <= cap, "SFO bounds/duplicate")
        raw = b[vals + vo : vals + vo + size]
        out[name] = raw.rstrip(b"\0").decode("utf8") if fmt == 0x0204 else None
    return out.get("TITLE_ID"), out.get("APP_VER")


def inspect(spec):
    ver, p, r, size, digest = spec
    receipt = json.loads(r.read_bytes())
    must((receipt["bytes"], receipt["sha256"]) == (size, digest), "VPK proof mismatch " + ver)
    if "members" in receipt:
        must((receipt.get("title"), receipt.get("app_ver")) == (TITLE, ver), "package receipt identity")
        proof_rows = receipt["members"]
    else:
        must(receipt["passed"] is True and receipt["sfo_patched"] == {"TITLE_ID": TITLE, "APP_VER": ver}, "base receipt identity")
        proof_rows = receipt["manifest"]["files"]
    data = {}
    rows = {}
    with p.open("rb") as stream:
        must(stream.seek(0, 2) == size, "archive bytes " + ver)
        stream.seek(0)
        must(filehash(stream) == digest, "archive SHA " + ver)
        stream.seek(0)
        with zipfile.ZipFile(stream) as z:
            must(len(z.namelist()) == len(NAMES) and set(z.namelist()) == set(NAMES), "archive layout")
            for name in NAMES:
                info = z.getinfo(name)
                must(info.flag_bits == 0 and info.compress_type in (0, 8) and 0 < info.file_size < 0xFFFFFFFF, "zip entry " + name)
                with z.open(info) as f:
                    if name in META:
                        must(info.file_size <= 16 * 1024, "metadata cap")
                        raw = f.read()
                        must(len(raw) == info.file_size, "metadata size")
                        data[name] = raw
                        sha = hash_bytes(raw)
                    else:
                        sha = filehash(f)
                rows[name] = {"bytes": info.file_size, "sha256": sha}
        stream.seek(0)
        must(filehash(stream) == digest, "source changed during audit")
    must(rows == proof_rows, "per-member receipt mismatch " + ver)
    must(sfo_identity(data[SFO]) == (TITLE, ver), "SFO identity " + ver)
    m = json.loads(data[MANIFEST])
    must((m.get("title_id"), m.get("app_ver"), m.get("eboot_sha256")) == (TITLE, ver, rows[EBOOT]["sha256"]), "game build manifest identity")
    must(m["files"] == {k: v for k, v in rows.items() if k != MANIFEST}, "in-package manifest members")
    return {"version": ver, "sfo_version": ver, "archive_bytes": size, "archive_sha256": digest, "members": rows}, data


def inspect_hybrid_0115(base12_row):
    pr = json.loads(EBOOT15_PROOF.read_bytes())
    must(pr.get("passed") is True and pr.get("app_ver") == "01.15" and pr.get("bytes") == EBOOT15_BYTES and pr.get("sha256") == EBOOT15_SHA,
         "invalid 01.15 eboot proof")
    with EBOOT15_PATH.open("rb") as f:
        must(EBOOT15_PATH.stat().st_size == EBOOT15_BYTES and filehash(f) == EBOOT15_SHA, "standalone 01.15 eboot mismatch")
    row = copy.deepcopy(base12_row)
    row["version"] = "01.15"
    row["sfo_version"] = "01.12"
    row["members"][EBOOT] = {"bytes": EBOOT15_BYTES, "sha256": EBOOT15_SHA}
    return row


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def validate(rows):
    expected_vers = ["01.09", "01.10", "01.12", "01.13", "01.15", VER]
    must([r["version"] for r in rows] == expected_vers, "unsupported base/target")
    target = rows[-1]["members"]
    spec_map = {s[0]: s[-2:] for s in PACKS}
    spec_map["01.15"] = spec_map["01.12"]
    for row in rows:
        must((row["archive_bytes"], row["archive_sha256"]) == spec_map[row["version"]], "untrusted archive identity")
        must(set(row["members"]) == set(NAMES), "missing/extra member")
        for name in NAMES:
            if name != EBOOT and name not in META:
                must(row["members"][name] == target[name], "unavailable target asset: " + name)
    must(rows[4]["members"][EBOOT] == {"bytes": EBOOT15_BYTES, "sha256": EBOOT15_SHA}, "01.15 base eboot mismatch")
    must(target[EBOOT] == {"bytes": BOOT_BYTES, "sha256": BOOT_SHA}, "target executable mismatch")
    return {"schema": "WB-APP-PATCH-RECIPE-v1", "title": TITLE, "bases": rows[:-1], "target": rows[-1]}


def render(obj, meta):
    must(set(meta) == set(META), "metadata allowlist")
    target = obj["target"]
    bases = obj["bases"]
    doc = canonical(obj)
    digest = hash_bytes(doc)
    lines = [
        "/* Generated by tools/gen_patch_recipe.py. Do not edit. No game executable or asset bytes included. */",
        "#ifndef WB_APP_PATCH_RECIPE_H",
        "#define WB_APP_PATCH_RECIPE_H",
        "#include <stdint.h>",
        "#include <stddef.h>",
        f'#define WB_PATCH_TITLE "{TITLE}"',
        f'#define WB_PATCH_VERSION "{VER}"',
        f'#define WB_PATCH_VPK_SHA "{target["archive_sha256"]}"',
        f'#define WB_PATCH_VPK_BYTES UINT64_C({target["archive_bytes"]})',
        f'#define WB_PATCH_RECIPE_SHA "{digest}"',
        f"#define WB_PATCH_FILE_COUNT {len(NAMES)}",
        f"#define WB_PATCH_BASE_COUNT {len(bases)}",
        "typedef struct { const char *path; uint64_t bytes; const char *sha; const unsigned char *embedded; } wb_patch_file;",
    ]
    ids = {SFO: "wb_patch_target_sfo", MANIFEST: "wb_patch_target_manifest"}
    for name, ident in ids.items():
        b = meta[name]
        entry = target["members"][name]
        must(len(b) == entry["bytes"] and hash_bytes(b) == entry["sha256"], "bad embedded " + name)
        lines.append(f"static const unsigned char {ident}[] = {{")
        lines.extend("    " + ",".join(f"0x{x:02x}" for x in b[i : i + 16]) + "," for i in range(0, len(b), 16))
        lines.extend(["};", f'_Static_assert(sizeof {ident} == {len(b)}, "metadata size");'])

    def table(row, embed):
        return [
            '    {"%s",UINT64_C(%d),"%s",%s},'
            % (name, row["members"][name]["bytes"], row["members"][name]["sha256"], ids.get(name, "NULL") if embed else "NULL")
            for name in NAMES
        ]

    lines.extend(["static const wb_patch_file wb_patch_target[WB_PATCH_FILE_COUNT] = {", *table(target, True), "};"])
    lines += [
        "static const char *const wb_patch_base_versions[WB_PATCH_BASE_COUNT] = {"
        + ",".join('"' + b["version"] + '"' for b in bases)
        + "};",
        "static const char *const wb_patch_base_sfo_versions[WB_PATCH_BASE_COUNT] = {"
        + ",".join('"' + b.get("sfo_version", b["version"]) + '"' for b in bases)
        + "};",
        "#define WB_PATCH_BASE_SFO_AT(i) (wb_patch_base_sfo_versions[i])",
        "static const wb_patch_file wb_patch_bases[WB_PATCH_BASE_COUNT][WB_PATCH_FILE_COUNT] = {",
    ]
    for b in bases:
        lines.extend(["  {", *table(b, False), "  },"])
    return ("\n".join(lines + ["};", "#endif", ""])).encode("ascii")


def generate():
    all_data = [inspect(s) for s in PACKS]
    raw_rows = [r for r, _ in all_data]
    hybrid15 = inspect_hybrid_0115(raw_rows[2])
    rows = raw_rows[:-1] + [hybrid15, raw_rows[-1]]
    obj = validate(rows)
    b = BASE / "build_0116/eboot.bin"
    with b.open("rb") as f:
        must(b.stat().st_size == BOOT_BYTES and filehash(f) == BOOT_SHA, "standalone eboot mismatch")
    return obj, render(obj, all_data[-1][1])


def publish(path, b):
    if path.exists():
        must(path.read_bytes() == b, "refusing to replace nonmatching file: " + str(path))
    else:
        with path.open("xb") as f:
            f.write(b)
    must(path.read_bytes() == b, "publication mismatch")


def main():
    a = argparse.ArgumentParser(description=__doc__)
    group = a.add_mutually_exclusive_group()
    group.add_argument("--emit", action="store_true")
    group.add_argument("--check", action="store_true", help="compare to compiled recipe (default)")
    a.add_argument("--manifest", type=Path, help="record exact canonical recipe for independent consumers")
    x = a.parse_args()
    obj, header = generate()
    if x.emit:
        publish(HEADER, header)
    else:
        must(HEADER.read_bytes() == header, "generated C recipe differs")
    if x.manifest:
        publish(x.manifest, canonical(obj))
    print(
        "PASS rehashed all 5 full VPKs, 66 members, 5 accepted base states and standalone 01.16 eboot; recipe_sha256="
        + hash_bytes(canonical(obj))
    )


if __name__ == "__main__":
    main()
