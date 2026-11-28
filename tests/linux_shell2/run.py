"""Compile and run the Workbench 2.0 (WB_SHELL2) shell host test."""
from pathlib import Path
import os, subprocess as sp, tempfile
here = Path(__file__).resolve().parent
src = here.parents[1] / 'source'
with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / ('linux_shell2.exe' if os.name == 'nt' else 'linux_shell2')
    sp.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-O2', '-DWB_SHELL2', '-DWB_SCREEN_MIRROR', '-I', str(src),
            str(here / 'fixture.c'),
            *[str(src / (n + '.c')) for n in ('wb_shell', 'wb_cmd', 'wb_out', 'wb_str', 'wb_sha256', 'wb_screen_mirror', 'wb_sftp_ro')],
            '-o', str(exe)], check=True)
    sp.run([str(exe)], check=True, timeout=15)
