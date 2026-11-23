"""Host verification of the production wrapper, with SDK calls replaced only at link time."""
from pathlib import Path
import os
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[1]
with tempfile.TemporaryDirectory() as td:
    exe = Path(td) / ("photo-native.exe" if os.name == "nt" else "photo-native")
    subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I"+str(root/"source"), "-I"+str(root/"tests/stub"),
                    str(root/"source/wb_vita_photo.c"), str(here/"fixture.c"),
                    "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
