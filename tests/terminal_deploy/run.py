"""Host-only: execute compiled production do_deploy with an inert byte-array stage/swap stub."""
from pathlib import Path
import subprocess,tempfile,zipfile

here=Path(__file__).resolve().parent
root=here.parents[1];src=root/"source"
code=(src/"vita_ssh_status.c").read_text(encoding="utf8")
fn=code[code.index("static int do_deploy("):code.index("static int do_rollback(")]
with tempfile.TemporaryDirectory() as td:
    temp=Path(td);(temp/"deploy.inc").write_text(fn,encoding="utf8")
    with zipfile.ZipFile(root.parent/'v1.64/build/workbench_0164.vpk') as z:
        (temp/"bytes.bin").write_bytes(z.read("workbench_payload.suprx"))
    exe=temp/"fixture.exe"
    subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror","-I",str(src),"-I",str(temp),
                    str(here/"fixture.c"),*[str(src/(n+".c")) for n in ("wb_sha256","wb_out","wb_path","wb_str","wb_err")],
                    "-o",str(exe)],check=True)
    subprocess.run([str(exe),str(temp/"bytes.bin")],check=True)
