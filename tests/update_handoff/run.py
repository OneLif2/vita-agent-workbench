"""Same host fixture, exact production launch functions for both releases; no device/network."""
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]


def func(src, prefix):
    # Both production functions independently end at a column-zero closing brace.
    a = src.index(prefix + "(void) {")
    return src[a:src.index("\n}", a) + 2]


with tempfile.TemporaryDirectory(prefix="wb-handoff-") as t:
    records = []
    for release, expected in [("v1.65", 0xFFFFF), ("v1.86", 0x20000)]:
        base = CANDIDATE if release == "v1.86" else CANDIDATE.parent / release
        core = (base / "source/wb_updater.c").read_text()
        updater = (base / "updater/main.c").read_text()
        version=re.search(r'^#define\s+WB_VERSION\s+"([^"]+)"', (base / "source/wb_ver.h").read_text(),re.M)[1]
        old = release == "v1.65"
        text = ('#include <stdio.h>\n#include "wb_err.h"\n#include "wb_ver.h"\n'
                '#include <psp2/appmgr.h>\n#include <psp2/io/fcntl.h>\n#include <psp2/io/stat.h>\n#include <psp2/rtc.h>\n')
        if old:
            text += next(line for line in updater.splitlines() if line.startswith("#define WORKBENCH_TITLE ")) + "\n"
        else:
            text += '#include "wb_handoff.h"\n'
        text += (func(core, "int wb_updater_launch") + "\n" + func(updater, "static int launch_workbench")
                 + "\n" + (HERE / "probe.c").read_text())
        p = Path(t) / f"{release}.c"
        p.write_text(text)
        exe = p.with_suffix(".exe")
        subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I"+str(base/"source"),
                        "-I"+str(base/"tests/stub"), str(p), "-o", str(exe)], check=True)
        for leg in ("out", "back"):
            for failure in ("ok", "launch-error", "log-error", "rtc-error"):
                a = subprocess.run([str(exe), leg, failure], text=True, capture_output=True, check=True)
                logged = not old and failure != "log-error"
                rc = -7 if failure == "launch-error" else 0
                lines = a.stdout.splitlines()
                assert lines[-1] == f"summary flags=0x{expected:X} rc={rc} calls=1 syncs={2 if logged else 0}"
                assert len(lines) == (4 if logged else 2)
                if logged:
                    arrow = "core->updater" if leg == "out" else "updater->core"
                    stamp = 0 if failure == "rtc-error" else 123456
                    prefix = f"handoff source={version} rtc_us={stamp} {arrow} "
                    assert lines[0] == prefix + "request rc=0x00000000"
                    assert lines[1].startswith("dispatch ")
                    assert lines[2] == prefix + f"reply rc=0x{rc & 0xFFFFFFFF:08X}"
                records.append(dict(release=release, leg=leg, mode=failure, rc=a.returncode,
                                    stdout=a.stdout, stderr=a.stderr,
                                    fixture_sha256=hashlib.sha256(text.encode()).hexdigest()))
                print(release, leg, failure, lines[-1])
    out = CANDIDATE / "evidence/host-update-handoff.json"
    out.write_text(json.dumps(dict(scope="Host only; no Sony UI, no device claim", cases=records), indent=2)
                   + "\n", encoding="utf8")
    print(f"{len(records)} passed; {out}")
