"""Run the native shell filesystem implementation against deterministic SDK I/O."""
import os, pathlib, subprocess, tempfile
r=pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as tmp:
    exe=pathlib.Path(tmp)/("test.exe" if os.name=="nt" else "test")
    subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror",
                    "-I",str(r/"tests/stub"),"-I",str(r/"source"),
                    str(pathlib.Path(__file__).with_name("fixture.c")),
                    str(r/"source/wb_shell_vfs.c"),str(r/"source/wb_out.c"),
                    "-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
