"""Actual App output streaming through shell channel and mirror, host-only.
No network, Vita, owner credentials, or device/control action.
"""
from pathlib import Path
import os
import subprocess
import tempfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
with tempfile.TemporaryDirectory(prefix='wb-app-progress-channel-') as tmp:
    exe=Path(tmp)/('channel.exe' if os.name=='nt' else 'channel')
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-DWB_SCREEN_MIRROR',
                    '-I'+str(ROOT/'source'),str(HERE/'fixture.c'),*[str(ROOT/'source'/(name+'.c')) for name in
                    ('wb_shell_channel','wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30)
