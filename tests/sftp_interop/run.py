"""Real OpenSSH sftp -D client and production read-only engine/framing in a
local child process. Exercises wire compatibility, NOT SSH or Vita hardware."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

src=Path(__file__).resolve().parents[2]/"source"
cc=shutil.which("gcc") or shutil.which("cc")
client=shutil.which("sftp"); assert client and cc, "requires OpenSSH sftp and a native C compiler"
with tempfile.TemporaryDirectory(prefix="wb-sftp-interop-") as temp:
    d=Path(temp)
    exe=d/("ro-fixture.exe" if os.name=="nt" else "ro-fixture")
    subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror","-I",str(src),
        str(Path(__file__).with_name("stdio_fixture.c")),str(src/"wb_sftp_frame.c"),
        str(src/"wb_sftp_ro.c"),"-o",str(exe)],check=True)
    (d/"scratch.bin").write_bytes(b"SFTP test data")
    cmds="""ls /sample
get -r /sample pulled
-mkdir /denied
-put scratch.bin /denied.bin
-rm /sample/top.bin
get /sample/top.bin after-denial.bin
quit
"""
    batch=d/"batch.txt";batch.write_text(cmds,encoding="ascii")
    # OpenSSH's -D is a local executable, not an SSH hostname. An absolute
    # temp executable name is quoted inside the direct-server argument.
    command=[client,"-B","8192","-R","4","-D",'"'+exe.as_posix()+'"',"-b",str(batch)]
    x=subprocess.run(command,cwd=d,capture_output=True,text=True,encoding="utf8",
                     errors="replace",env={**os.environ,"LC_ALL":"C","LANG":"C"},timeout=30)
    print("OpenSSH sftp -D (no network) exit",x.returncode)
    print(x.stdout);print(x.stderr)
    assert x.returncode==0
    assert "top.bin" in x.stdout
    # mkdir, upload and delete must each report failure while the same client
    # continues to read the original fixture afterwards.
    assert x.stderr.lower().count("permission denied")>=3, "did not observe all denials"
    actual=d/"pulled";expected={"a/b/payload.bin":76543,"zero.bin":0,"top.bin":17}
    assert {p.relative_to(actual).as_posix() for p in actual.rglob("*") if p.is_file()}==set(expected)
    assert (actual/"spare").is_dir() and not any((actual/"spare").iterdir())
    for path,size in expected.items():
        blob=(actual/path).read_bytes()
        assert blob==bytes(i%251 for i in range(size))
        print("SHA256",path,len(blob),hashlib.sha256(blob).hexdigest())
    assert (d/"after-denial.bin").read_bytes()==(actual/"top.bin").read_bytes()
    print("PASS OpenSSH list, recursive binary transfer, empty file/directory, three writes denied, sustained read after denial")
