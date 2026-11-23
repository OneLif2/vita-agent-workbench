"""Verify a fixed approved INAP00019 binary pair and the sources used for that epoch.
A core version bump alone never remints the helper. An intentional helper change
requires its own compatibility review. The existing Vita helper is never read here.
"""
import hashlib, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
EPOCH = ROOT / "updater/epoch-0174"
PINS = {"eboot.bin": (161438, "3db1718a22be8c4a2916e41e2dae1d1930fd881c958b7163862f76b6093deb3b"),
        "param.sfo": (912, "1dba3e69e2647c12bf6a094c291dc210cdc651b7bbad11c3d6cdef63b3a4fe1b")}
def digest(data): return hashlib.sha256(data).hexdigest()
def pinned():
    manifest = json.loads((EPOCH / "manifest.json").read_bytes())
    if manifest["from_core_vpk_sha256"] != "efe4906fc777f619c52d8865e1878b056b3a574ebddbfba7af8f8423ac36179e":
        raise ValueError("unexpected helper provenance")
    data = {}
    for filename, pair in PINS.items():
        b = (EPOCH / filename).read_bytes()
        if (len(b), digest(b)) != pair or manifest["files"][filename] != list(pair):
            raise ValueError("unapproved frozen helper member: " + filename)
        data[filename] = b
    for name, expected in manifest["sources"].items():
        b = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        if name == "source/wb_ver.h":
            b = re.sub(rb"(?m)^#define WB_(?:VERSION|BUILD_TAG) [^\n]*\n", b"", b)
        if digest(b) != expected:
            raise ValueError("helper source drift; review a new helper epoch before release: "+name)
    return data
if __name__ == "__main__":
    out = Path(sys.argv[1])
    for name, b in pinned().items():
        (out / name).write_bytes(b)
        if (out / name).read_bytes() != b: raise OSError("epoch copy failed")
    print("PASS: approved INAP00019 epoch 01.74, source guard + exact SELF and SFO")
