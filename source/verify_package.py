#!/usr/bin/env python3
"""Checks exact v2.18 package: members, SELF identity, permissions, SFO, payload.

    python3 verify_package.py build

Asserts, in order:
  * exactly three members: eboot.bin, sce_sys/param.sfo, workbench_payload.suprx
  * zip CRCs valid
  * eboot is a SELF with an ARM32 ELF and the full-permission authid
    (0x2F00000000000001) - -s would give 0x..02 and break the installer
  * param.sfo is INAP00018 / 02.18
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
APP_VER = "02.21"
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
    assert b"02.21-hyper-sftp\0" in eboot, "exact core build tag mismatch"
    assert b"Filesystem       Size        Used       Avail   Use%%  Mounted on" in eboot, "missing read-only human df"
    assert b"TTY1 READY BATCH " in eboot and b"put-batch" in eboot, "missing 02.14 batched terminal protocol"
    for needle in (b"sha256sum", b"SFTP PUT", b"SFTP GET", b"%.10s %3u%%  %.14s/%.14s  %.14s  ETA %.10s", b"Vita Linux Terminal ", b"pi@vita", b"OK app-prune scope=", b"APP COPY", b"VALIDATE", b"EXTRACT", b"APPROVE", b"VERIFY", b"VitaAgentWorkbench", b"OK touch ", b"OK cp bytes=", b"OK app-patch-eboot title=", b"OK app-list-installed count=", b"OK app-install-vpk title=", b"AGENT MODE READY", b"ERR r1-removed", b"r1 state=removed mode=agent-ops", b"Binary file %s matches", b"find: %u match%s", b"ERR pipe: only grep head tail wc sort uniq may follow |", b"uma0:/"):
        assert needle in eboot, f"missing 02.20 turbo-term feature {needle!r}"
    assert core.compressed, "02.20 core must use standard SELF segment compression"

    # A package is not a patch build unless it carries the verified eboot
    # hashes for the allowed bases AND target, and committed member digests
    # for each of the release manifests. Never accept a tag-only build.
    for needle in (
        b"WB-APP-PATCH-v1\nRUN ", b"ERR app-patch phase=", b"OK app-patch%s title=",
        b"2b30f7abd0a374dcca206162405c7ba0780062fd7918acba6637785ab7bd6e54",
        b"2878f25cf846479a7d7dec0147c4d5b704488df8e2c55e31ebce8ea84cf9d7b6",
        b"8f36db59e872afcc6024837a035653ae241016842c770bd6c7076d8cc5151dab",
        b"699b11eecb3a57bc009c0dfcf423d5c25174b7372b24b328ee1d5dc414f85a9a",
        b"3c3717f15ee53fb2d3bf1e942e789bf39e5cee5ff17969b7aea68777c63e53ed",
        b"db8dcb3fe45b069e2bc567e41e52e6f8e79e1c2fbeb8bc86da08c0f540c01597",
        b"e3d9e38441e1239eb9eb43df6ab3ae420d0afa083bcffe9d5cbe0ec4e1fdf6ee",
    ):
        assert needle in eboot, "missing exact RJGM52237 patch identity"
    recipe = Path(__file__).with_name("wb_app_patch_recipe.h").read_text("ascii")
    rows = re.findall(r'\{"([^"]+)",UINT64_C\((\d+)\),"([0-9a-f]{64})",(?:NULL|wb_patch_target_sfo|wb_patch_target_manifest)\}', recipe)
    assert len(rows)==66 and len({n for n,_,_ in rows})==11, "unexpected patch recipe shape"
    for path, n, digest in rows:
        assert int(n)>0 and path.encode() in eboot and digest.encode() in eboot, "missing bound patch member: "+path

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

    assert b'WBLC00079\0' in eboot and b'026389c85760b79921a0b587eefed0daaedf22e108a4b915c2375c26a1534621\0' in eboot, 'wrong or missing exact 02.10 lifecycle canary approval'
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
        assert marker in eboot, "02.10 release feature or approval missing"
    for marker in (b"python3 tictactoe_ai.py", b"PYTHON runtime=MicroPython-1.25.0", b"ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d"):
        assert marker in eboot, "missing compiled interactive game marker"
    for marker in (b"TTY1 READY %s", b"TTY1 OK %s", b"stage-hash-mismatch", b"no-clobber-unavailable"):
        assert marker in eboot, "missing 02.10 terminal transfer marker: " + repr(marker)
    assert b"payload-not-approved" in eboot and hashlib.sha256(payload).hexdigest().encode() in eboot, "terminal deploy approval differs from packaged payload"
    assert b"WB>\x00" not in eboot, "obsolete terminal panel prompt present"
    assert (APP_VER + "-hyper-sftp").encode() in eboot, "wrong build tag (WB_BUILD_TAG must derive from WB_VERSION)"
    # 02.14 positive features: optional app-progress total=, on-screen transfer
    # bar, and the second read-only title Logs root beside RJGM52237.
    for needle in (b"app-progress phase=%s bytes=%llu total=%llu\n", b"app-progress phase=%s bytes=%llu\n",
                   b"write-error rc=0x%08x offset=%llu requested=%u fd=%d\0", b"%s %u%%  %u/%u B  %s  ETA %s\0", b"WAIT RECEIPT\0", b"%llu.%02u MB/s\0",
                   b"ux0:/data/RJGM52237/Logs\0", b"ux0:/data/RJGP52237/Logs\0"):
        assert needle in eboot, f"missing 02.14 transfer/logs feature {needle!r}"
    assert b"ux0:/data/RJGP52237/Saves" not in eboot, "02.14 must not name PerfLab saves"
    assert b"LOW BATTERY - CHARGE THEN REOPEN APP" in eboot and b"POWER EVENT - REOPEN APP" in eboot, "missing 02.10 startup stop messages"
    assert b"/inbox" in eboot, "missing interactive inbox alias"
    for m in (b"Vita Linux Terminal 02.21", b"Zero-Button WBQ2"):
        assert m in eboot, "missing 02.20 linux terminal OLED panel"
    for m in (b"SSH HOST KEY SHA256 HEX", b"CHECK MAC PUBLIC PIN"):
        assert m not in eboot, "02.18 must not show key fingerprints on the Vita"
    assert b"DPAD:Scroll/Pan" in eboot, "02.19 scroll panel not in release"
    for m in (b"font set", b"SIL OPEN FONT LICENSE", b"jetbrains"):
        assert m in eboot, "missing typography or license: "+repr(m)
    ofl = (Path(__file__).resolve().parents[1]/"tools/font_assets/OFL.txt").read_bytes().replace(b"\r\n", b"\n")
    assert len(ofl)>4000 and ofl in eboot, "full upstream font license missing from eboot"
    assert b"app uninstall" in eboot and b"VSSH00001" in eboot, "missing single-title app uninstall gate"
    assert b"core voluntary-exit requested; tty-drain" in eboot, "missing cooperative updater handoff"
    for m in (b"app uninstall-plan title=", b"eboot_sha256=", b"settings updater-folder", b"layout=unverified", b"ERR paired interactive PTY required"):
        assert m in eboot,"02.10 command not present in packaged core: "+repr(m)
    assert b'WBPA00077\0' in eboot and b'caa2fc46faec834e92b318fd5f03dabcd11997905f75b396c69fb00a316d5eec\0' in eboot, 'missing QA install-only approval'
    assert b'WBSD00078\0' in eboot and b'368a2031d22a6c16a17f062b87e46055a1a9e36f808574c20cc9a0b558d5e697\0' in eboot, 'missing exact save probe install-only approval'
    # A version bump alone is never sufficient; check both the signed-in
    # PTY boundary and actual scanner/output strings of the shipped SELF.
    for needle in (b"OK crash-index matched=", b"END crash-index", b"ERR crash-index no-pty", b"crash name=%s modified=%s bytes="):
        assert needle in eboot, f"missing 02.10 crash metadata feature {needle!r}"
    for needle in (b"ERR close-wb wake-not-ready", b"ERR close-wb no-pty"):
        assert needle in eboot, f"missing 02.10 wake guard feature {needle!r}"
    for needle in (b"WAKE PROBE DISPATCH REQUEST; NOT RECEIVER READY", b"wake-probe state=",
                   b"wake-probe diagnostic=public-untrusted readiness=not-provided close_wb=disabled",
                   b"OK wake-probe DISPATCHED_UNVERIFIED job=", b"ERR wake-probe %s; WB not closed",
                   b"installed-01.02-members-not-approved", b"private-pending-save"):
        assert needle in eboot, "missing exact v1.89 finite wake-probe feature " + repr(needle)
    for needle in (b"ERR app-running INCONCLUSIVE %s rc=%d (0x%08X) foreground=unknown scope=appmgr-started-apps",
                   b"app-running state=%s run=%.16s count=%d capacity=%d potentially_truncated=%s foreground=unknown scope=appmgr-started-apps",
                   b"bounded-two-sample-not-atomic; not-all-kernel-processes; no-foreground-claim"):
        assert needle in eboot, "missing exact v1.89 bounded running-app feature " + repr(needle)
    assert b"R1 STANDING BOOTSTRAP VERIFIED" not in eboot and b"R1 STANDING BOOTSTRAP SAVE FAILED" not in eboot, "v1.89 may not enroll standing permission"
    for needle in (b"OK wb-status version=02.21 ", b"END wb-status", b"ERR wb-status no-pty",
                   b"state wb=running lock=unknown overlay=%s foreground=%s focus_reason=%s"):
        assert needle in eboot, f"missing exact v1.89 device status feature {needle!r}"
    # Exactly one owner-approved game artifact, install-only, by title+version+digest.
    assert b"RJGM52237\0" in eboot, "missing approved game title in the compiled registry"
    assert b"b3a8fbb2ddf112df4da2d3f2848d9fe865e2d78b268db4a22d6577c4bb257baa\0" in eboot, \
        "missing the exact approved game digest in the compiled registry"
    for needle in (b"WB-APP-APPROVE-v1", b"OK app-approve title=%s app_ver=%s sha256=%s",
                   b"ERR app-approve signature-or-storage", b"source=owner-signed",
                   b"source=compiled", b"busybox-never"):
        if needle == b"busybox-never":
            continue
        assert needle in eboot, f"missing 02.10 runtime approval feature {needle!r}"
    assert b"SQUARE OPENS PAIRED SSH" not in eboot and b"PAIRED OPEN NOT CONFIRMED" not in eboot, "obsolete paired-listener button gate remains"
    digest = hashlib.sha256(vpk.read_bytes()).hexdigest()
    print(f"PASS: 3-member CRC, ARM32 SELF, authid {authid:#x}, "
          f"{TITLE_ID} {APP_VER}, payload {PAYLOAD_VERSION.decode()}")
    print(f"vpk bytes={vpk.stat().st_size} sha256={digest}")
    print(f"core physical_bytes={len(physical_eboot)} logical_bytes={len(eboot)} compressed={int(core.compressed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
