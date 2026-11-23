"""Exercise the exact handle_channel admission code from a supplied Workbench tree.

Host-only: the SSH message, existing authentication result and current core gate
are fixture inputs. Does not connect, enroll a peer, simulate a login or mock the
decision being tested. Run unchanged against a baseline, candidate or rollback.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
args = parser.parse_args()
src = args.source.resolve(strict=True)
here = Path(__file__).resolve().parent
code = (src / "wb_ssh.c").read_text(encoding="utf8")

def definition(name):
    # File-scope static C definitions here either end on the same line, or
    # the final '}' is flush left. Include original text unchanged.
    m = re.search(r"(?m)^static [^\n;]*?\b" + re.escape(name) + r"\([^;\n]*\)\s*\{", code)
    if m is None:
        raise ValueError("missing production function: " + name)
    line_end = code.index("\n", m.end())
    if code[m.end():line_end].rstrip().endswith("}"):
        return code[m.start():line_end]
    end = re.search(r"(?m)^\}\s*$", code[m.end():])
    if not end:
        raise ValueError("unterminated production function: " + name)
    return code[m.start():m.end() + end.end()].rstrip()

# Classify the dependencies of the selected definition, not the version number
# or files elsewhere in its directory (an overlay rollback may retain headers).
has_engine = "sftp_admitted(" in definition("handle_channel")
has_shell = "wb_sh_start(" in definition("handle_channel")
names = ["now_ms", "refresh_idle"]
if has_engine:
    names += ["end_sftp", "sftp_admitted"]
if has_shell:
    names += ["end_shell","shell_service"]
names += ["finish_channel", "handle_channel"]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / "actual.inc").write_text("\n".join(map(definition, names))+"\n", encoding="utf8")
    exe = tmp / ("admission.exe" if os.name=="nt" else "admission")
    cmd = ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(src),
           "-I", str(here.parents[0] / "stub"), "-I", str(tmp), str(here / "fixture.c")]
    if has_engine:
        cmd += ["-DCANDIDATE_API", str(src / "wb_sftp_ro.c"), str(src / "wb_sftp_vita.c"),
                str(src / "wb_path.c")]
    if has_shell:
        cmd += ["-DSHELL_API",str(src/"wb_shell_channel.c"),str(src/"wb_shell.c"),
                str(src/"wb_out.c"),str(src/"wb_str.c"),str(src/"wb_cmd.c")]
    subprocess.run(cmd + ["-o",str(exe)], check=True)
    subprocess.run([str(exe)],check=True)
    if has_shell and 'wb_sh_set_geometry' in code:
        subprocess.run(cmd+["-DWB_SCREEN_MIRROR","-o",str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
        print("PASS: mirrored authentic PTY admission isolation and permitted/denied terminal dimension changes")
    if "wb_sftp_enable_write(" in code:
        subprocess.run(cmd+["-DWB_TTY_FILE","-DWB_SCREEN_MIRROR",str(src/"wb_tty_file.c"),
                             str(src/"wb_sha256.c"),"-o",str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
        print("PASS: exact production writable SFTP attach occurs only on approved authenticated channel; no filesystem access at admission")
