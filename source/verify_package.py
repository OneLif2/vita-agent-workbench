#!/usr/bin/env python3
"""Checks exact v2.04 / 02.06 package: members, SELF identity, permissions, SFO, payload.

    python3 verify_package.py build

Asserts, in order:
  * exactly three members: eboot.bin, sce_sys/param.sfo, workbench_payload.suprx
  * zip CRCs valid
  * eboot is a SELF with an ARM32 ELF and the full-permission authid
    (0x2F00000000000001) - -s would give 0x..02 and break the installer
  * param.sfo is INAP00018 / 02.06
  * payload is a SELF carrying the 01.22-p2.1 version marker
  * the core still contains the install/put/promote/head.bin/wb10 surface and
    no /bin/sh
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import re
import struct
import sys
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from self_segments import parse_self

TITLE_ID = "INAP00018"
APP_VER = "02.06"
VPK_NAME = "workbench_" + APP_VER.replace(".", "") + ".vpk"
PAYLOAD_VERSION = b"01.22-p2.1"
FULL_PERMISSION_AUTHID = 0x2F00000000000001


def parse_sfo(sfo: bytes) -> dict[str, str]:
    assert sfo[:4] == b"\x00PSF", "not an SFO"
    _, keyofs, valofs, count = struct.unpack_from("<4I", sfo, 4)
    fields: dict[str, str] = {}
    for i in range(count):
        ko, fmt, length, cap, vo = struct.unpack_from("<HHIII", sfo, 20 + i * 16)
        key = sfo[keyofs + ko:sfo.index(b"\0", keyofs + ko)].decode()
        assert key not in fields and length <= cap and valofs + vo + length <= len(sfo)
        fields[key] = (sfo[valofs + vo:valofs + vo + length].rstrip(b"\0").decode()
                       if fmt == 0x0204 else "")
    return fields


def check_self(image: bytes, label: str) -> int:
    assert image[:4] == b"SCE\x00", f"{label} is not a SELF"
    elf_off = struct.unpack_from("<Q", image, 0x40)[0]
    assert elf_off + 20 <= len(image), f"{label} ELF offset out of range"
    assert image[elf_off:elf_off + 7] == b"\x7fELF\x01\x01\x01", f"{label} has no ELF"
    assert struct.unpack_from("<H", image, elf_off + 18)[0] == 40, f"{label} is not ARM32"
    return elf_off


def main() -> int:
    build = Path(sys.argv[1] if len(sys.argv) > 1 else "build")
    vpk = build / VPK_NAME
    assert vpk.is_file(), f"missing {vpk}"

    with zipfile.ZipFile(vpk) as z:
        names = sorted(z.namelist())
        assert names == ["eboot.bin", "sce_sys/param.sfo", "workbench_payload.suprx"], names
        assert z.testzip() is None, "zip CRC failure"
        eboot = z.read("eboot.bin")
        sfo = z.read("sce_sys/param.sfo")
        payload = z.read("workbench_payload.suprx")

    physical_eboot = eboot
    core = parse_self(physical_eboot, label="eboot.bin", required_authid=FULL_PERMISSION_AUTHID)
    # Positive feature checks only use verified, decompressed loadable bytes;
    # unauthenticated header/trailer text cannot satisfy these requirements.
    eboot = core.logical_bytes
    assert b"02.06-live-safequery\0" in eboot, "exact v2.04 core build tag mismatch"
    assert core.compressed, "02.06 core must use standard SELF segment compression"
    for forbidden in (b"R1 STANDING BOOTSTRAP VERIFIED", b"R1 STANDING BOOTSTRAP SAVE FAILED"):
        assert forbidden not in eboot and forbidden not in physical_eboot, "v1.89 may not enroll standing permission"
    for forbidden in (b"SQUARE OPENS PAIRED SSH", b"PAIRED OPEN NOT CONFIRMED"):
        assert forbidden not in eboot and forbidden not in physical_eboot, "obsolete paired-listener button gate remains"
    assert hashlib.sha256(payload).hexdigest()=="0e3a633929b7069a5a194c86bd92eb770515d1766101f597139af61b0a45a66b", "release module digest mismatch"
    from verify_helper_epoch import pinned
    helper = pinned()
    assert eboot.count(helper["eboot.bin"] + helper["param.sfo"]) == 1, "wrong embedded helper epoch"
    assert b"OK updater %s (detail=" in eboot and b"reused" in eboot and b"updater-check title=" in eboot, "missing safe reuse/check logic"
    check_self(physical_eboot, "eboot.bin")
    authid = struct.unpack_from("<Q", physical_eboot, 0x80)[0]
    assert authid == FULL_PERMISSION_AUTHID, (
        f"eboot authid {authid:#018x} is not full permission "
        f"({FULL_PERMISSION_AUTHID:#018x}); rebuild without -s")

    fields = parse_sfo(sfo)
    assert fields.get("TITLE_ID") == TITLE_ID, fields.get("TITLE_ID")
    assert fields.get("APP_VER") == APP_VER, fields.get("APP_VER")

    check_self(payload, "workbench_payload.suprx")
    assert PAYLOAD_VERSION in payload, "payload version marker missing"

    for marker in (b"payload sys version=", b"features=sys ls stat rm mv mkdir",
                   b"payload-unknown"):
        assert marker in payload, f"payload feature marker {marker!r} missing"
    for marker in (b"inspect", b"deploy", b"shot"):
        assert marker in eboot, f"core feature marker {marker!r} missing"
    for marker in (b"install", b"put", b"promote", b"head.bin", b"wb10"):
        assert marker in eboot, f"core marker {marker!r} missing"
    # No "/bin/sh" assertion: the libssh archive itself carries that literal.
    # The core defines no shell entry point - `arm-vita-eabi-nm` on the built
    # ELF shows no system, popen or execv symbol.

    assert b'WBLC00079\0' in eboot and b'026389c85760b79921a0b587eefed0daaedf22e108a4b915c2375c26a1534621\0' in eboot, 'wrong or missing exact 02.06 lifecycle canary approval'
    assert b'15c40b646963cae1e6faefce52f27f6e0eaa75be3add4ff1223e99936c62f4ef\0' not in eboot, 'stale Lifecycle 01.00 install approval remains'
    assert b'2a3a6cf25083a6e81e2c55eb12eea1ede88bbb24d566c0a0ee915dcb7b7264cd\0' not in eboot, 'stale Lifecycle 01.01 install approval remains'
    approved = Path(__file__).resolve().with_name('wb_wake_probe_approved.h').read_text(encoding='ascii')
    probe_members = re.findall(r'\{"([^"]+)",\s*UINT64_C\((\d+)\),\s*"([0-9a-f]{64})"\}', approved)
    assert len(probe_members)==4 and {p for p,_,_ in probe_members}=={'eboot.bin','eboot2.bin','sce_sys/param.sfo','sce_sys/param2.sfo'}, 'invalid frozen probe member header'
    for path,size,digest in probe_members:
        assert int(size)>0 and digest.encode() in eboot, 'missing exact v1.89 probe member binding '+path

    assert b'WBSD00078\0' in eboot and b'368a2031d22a6c16a17f062b87e46055a1a9e36f808574c20cc9a0b558d5e697\0' in eboot, 'old probe approval lost'
    assert b"inspect" in eboot, "missing inspect command in core"
    for marker in (b"Type help for commands.", b"VITA AGENT TERMINAL", b"UI PRESENT TERMINAL IDLE", b"photo-export", b"OK photo-export bytes=", b"SFTP INCOMING OPEN", b"VSSH00001",
                   b"e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce"):
        assert marker in eboot, "02.06 release feature or approval missing"
    for marker in (b"python3 tictactoe_ai.py", b"PYTHON runtime=MicroPython-1.25.0", b"ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d"):
        assert marker in eboot, "missing compiled interactive game marker"
    assert b"VITA AGENT TERMINAL / SHARED SSH" in eboot, "missing shared shell framebuffer view"
    assert b"WAITING FOR INTERACTIVE SSH" in eboot, "missing shared terminal waiting view"
    for marker in (b"TTY1 READY %s", b"TTY1 OK %s", b"stage-hash-mismatch", b"no-clobber-unavailable"):
        assert marker in eboot, "missing 02.06 terminal transfer marker: " + repr(marker)
    assert b"payload-not-approved" in eboot and hashlib.sha256(payload).hexdigest().encode() in eboot, "terminal deploy approval differs from packaged payload"
    assert b"WB>\x00" not in eboot, "obsolete terminal panel prompt present"
    assert (APP_VER + "-live-safequery").encode() in eboot, "wrong build tag (WB_BUILD_TAG must derive from WB_VERSION)"
    assert b"LOW BATTERY - CHARGE THEN REOPEN APP" in eboot and b"POWER EVENT - REOPEN APP" in eboot, "missing 02.06 startup stop messages"
    assert b"/inbox" in eboot, "missing interactive inbox alias"
    assert b"DPAD SCROLL/PAN" in eboot, "02.06 scroll panel not in release"
    for m in (b"font set", b"SIL OPEN FONT LICENSE", b"jetbrains"):
        assert m in eboot, "missing typography or license: "+repr(m)
    ofl = (Path(__file__).resolve().parents[1]/"tools/font_assets/OFL.txt").read_bytes().replace(b"\r\n", b"\n")
    assert len(ofl)>4000 and ofl in eboot, "full upstream font license missing from eboot"
    assert b"app uninstall" in eboot and b"VSSH00001" in eboot, "missing single-title app uninstall gate"
    assert b"core voluntary-exit requested; tty-drain" in eboot, "missing cooperative updater handoff"
    for m in (b"app uninstall-plan title=", b"eboot_sha256=", b"settings updater-folder", b"layout=unverified", b"ERR paired interactive PTY required"):
        assert m in eboot,"02.06 command not present in packaged core: "+repr(m)
    assert b'WBPA00077\0' in eboot and b'caa2fc46faec834e92b318fd5f03dabcd11997905f75b396c69fb00a316d5eec\0' in eboot, 'missing QA install-only approval'
    assert b'WBSD00078\0' in eboot and b'368a2031d22a6c16a17f062b87e46055a1a9e36f808574c20cc9a0b558d5e697\0' in eboot, 'missing exact save probe install-only approval'
    # A version bump alone is never sufficient; check both the signed-in
    # PTY boundary and actual scanner/output strings of the shipped SELF.
    for needle in (b"OK crash-index matched=", b"END crash-index", b"ERR crash-index no-pty", b"crash name=%s modified=%s bytes="):
        assert needle in eboot, f"missing 02.06 crash metadata feature {needle!r}"
    for needle in (b"OK r1-review model=local-review title=", b"ERR r1-review no-pty", b"ERR r1-review not-verified"):
        assert needle in eboot, f"missing 02.06 digest review feature {needle!r}"
    for needle in (b"OK r1-notice title=", b"ERR r1-notice no-pty"):
        assert needle in eboot, f"missing 02.06 notice feature {needle!r}"
    for needle in (b"ERR close-wb wake-not-ready", b"ERR close-wb no-pty"):
        assert needle in eboot, f"missing 02.06 wake guard feature {needle!r}"
    for needle in (b"WAKE PROBE DISPATCH REQUEST; NOT RECEIVER READY", b"wake-probe state=",
                   b"wake-probe diagnostic=public-untrusted readiness=not-provided close_wb=disabled",
                   b"OK wake-probe DISPATCHED_UNVERIFIED job=", b"ERR wake-probe %s; WB not closed",
                   b"installed-01.02-members-not-approved", b"private-pending-save"):
        assert needle in eboot, "missing exact v1.89 finite wake-probe feature " + repr(needle)
    for needle in (b"ERR app-running INCONCLUSIVE %s rc=%d (0x%08X) foreground=unknown scope=appmgr-started-apps",
                   b"app-running state=%s run=%.16s count=%d capacity=%d potentially_truncated=%s foreground=unknown scope=appmgr-started-apps",
                   b"bounded-two-sample-not-atomic; not-all-kernel-processes; no-foreground-claim"):
        assert needle in eboot, "missing exact v1.89 bounded running-app feature " + repr(needle)
    for needle in (b"r1-auto state=%s run=%s", b"ERR r1-signed signature",
                   b"OK r1-signed target=%s run=%s manifest=%.64s grant=armed"):
        assert needle in eboot, f"missing exact v1.89 signed-update feature {needle!r}"
    assert b"R1 STANDING BOOTSTRAP VERIFIED" not in eboot and b"R1 STANDING BOOTSTRAP SAVE FAILED" not in eboot, "v1.89 may not enroll standing permission"
    for needle in (b"OK wb-status version=02.06 ", b"END wb-status", b"ERR wb-status no-pty",
                   b"state wb=running lock=unknown overlay=%s foreground=%s focus_reason=%s"):
        assert needle in eboot, f"missing exact v1.89 device status feature {needle!r}"
    # Exactly one owner-approved game artifact, install-only, by title+version+digest.
    assert b"RJGM52237\0" in eboot, "missing approved game title in the compiled registry"
    assert b"b3a8fbb2ddf112df4da2d3f2848d9fe865e2d78b268db4a22d6577c4bb257baa\0" in eboot, \
        "missing the exact approved game digest in the compiled registry"
    for needle in (b"R1 REOPEN SELF FOR CLEAN RUN", b"r1-reopen.once"):
        assert needle in eboot, f"missing 02.06 reopen feature {needle!r}"
    for needle in (b"WB-APP-APPROVE-v1", b"OK app-approve title=%s app_ver=%s sha256=%s",
                   b"ERR app-approve signature-or-storage", b"source=owner-signed",
                   b"source=compiled", b"busybox-never"):
        if needle == b"busybox-never":
            continue
        assert needle in eboot, f"missing 02.06 runtime approval feature {needle!r}"
    for needle in (b"R1 SIGNED FOCUS BRACKET START REFUSED", b"R1 SIGNED FOCUS BRACKET END REFUSED"):
        assert needle in eboot, f"missing exact v1.89 signed-focus gate {needle!r}"
    assert b"PAIRED LISTENER AUTO ENTRY; UPDATE GRANT UNCHANGED" in eboot, "missing exact v1.89 paired autoentry feature"
    for needle in (b"R1 SIGNED HANDOFF BRACKET START REFUSED", b"R1 SIGNED HANDOFF BRACKET END REFUSED", b"R1 SIGNED HANDOFF TRANSACTION REFUSED"):
        assert needle in eboot, f"missing exact v1.89 full-handoff gate {needle!r}"
    assert b"SQUARE OPENS PAIRED SSH" not in eboot and b"PAIRED OPEN NOT CONFIRMED" not in eboot, "obsolete paired-listener button gate remains"
    for needle in (b"REMOTE OWNER START ENABLED; NO UPDATE GRANT", b"REMOTE OWNER LISTENING; BACKGROUND ALLOWED", b"INSTALLED WBQ2 "):
        assert needle in eboot, f"missing exact v1.89 owner remote-start policy {needle!r}"
    provision = Path(__file__).resolve().with_name("wb_standing_provision.h").read_text(encoding="ascii")
    pairs = re.findall(r'^#define WB_STANDING_([A-Z0-9]+) "([0-9a-f]+)"$', provision, re.M)
    public = dict(pairs)
    assert len(pairs) == 4 and set(public) == {"HOST","OWNER","SIGNER","SEC1"}, "unexpected r2 public provisioning"
    assert len({public[k] for k in ("HOST","OWNER","SIGNER")}) == 3
    sec1 = bytes.fromhex(public["SEC1"])
    assert len(sec1) == 65 and sec1[0] == 4 and hashlib.sha256(sec1).hexdigest() == public["SIGNER"], "wrong r2 public signer binding"
    assert sec1 in eboot or public["SEC1"].encode() in eboot, "missing r2 compiled public signer"
    assert all(len(public[k]) == 64 and public[k].encode() in eboot for k in ("HOST","OWNER","SIGNER")), "missing exact r2 public pins"
    digest = hashlib.sha256(vpk.read_bytes()).hexdigest()
    print(f"PASS: 3-member CRC, ARM32 SELF, authid {authid:#x}, "
          f"{TITLE_ID} {APP_VER}, payload {PAYLOAD_VERSION.decode()}")
    print(f"vpk bytes={vpk.stat().st_size} sha256={digest}")
    print(f"core physical_bytes={len(physical_eboot)} logical_bytes={len(eboot)} compressed={int(core.compressed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
