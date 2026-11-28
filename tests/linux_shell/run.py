"""Compile and run host unit tests for 02.17 Linux-style terminal commands."""
from pathlib import Path
import os, subprocess as sp, tempfile
here = Path(__file__).resolve().parent
src = here.parents[1] / 'source'
with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / ('linux_shell.exe' if os.name == 'nt' else 'linux_shell')
    sp.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-I', str(src),
            str(here / 'fixture.c'),
            *[str(src / (n + '.c')) for n in ('wb_shell', 'wb_cmd', 'wb_out', 'wb_str', 'wb_sha256')],
            '-o', str(exe)], check=True)
    sp.run([str(exe)], check=True, timeout=15)
