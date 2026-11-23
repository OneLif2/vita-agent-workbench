"""Compile production editor and fixed-game queues with a capture-only OLED.
No network or device. Game launch admission and filesystem are fixtures."""
from pathlib import Path
import tempfile, subprocess, os
h=Path(__file__).resolve().parent;src=h.parents[1]/'source'
with tempfile.TemporaryDirectory() as t:
    exe=Path(t)/('wire.exe' if os.name=='nt' else 'wire')
    cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-DWB_GAME_FEATURE','-DWB_SCREEN_MIRROR',
         '-I'+str(src),str(h/'wire.c'),*[str(src/(p+'.c')) for p in ('wb_shell_channel','wb_game_io','wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(exe)]
    subprocess.run(cmd,check=True);subprocess.run([str(exe)],check=True,timeout=15)
