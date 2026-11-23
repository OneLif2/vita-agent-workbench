"""Exercise the production v3 codec using a deterministic host filesystem on pipes."""
from pathlib import Path
import hashlib, os, shutil, struct, subprocess, tempfile

HERE=Path(__file__).resolve().parent
SRC=HERE.parents[1]/"source"
def u32(n):return struct.pack(">I",n)
def u64(n):return struct.pack(">Q",n)
def s(b):return u32(len(b))+b
def num(b):return int.from_bytes(b,"big")
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);exe=d/("sftpfixture.exe" if os.name=="nt" else "sftpfixture")
    subprocess.run(["gcc","-std=c11","-Wall","-Wextra","-Werror","-I",str(SRC),
                    str(SRC/"wb_sftp_ro.c"),str(HERE/"stdio.c"),"-o",str(exe)],check=True)
    p=subprocess.Popen([str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    try:
        def exchange(body):
            p.stdin.write(s(body));p.stdin.flush()
            n=p.stdout.read(4);assert len(n)==4,"no SFTP response"
            data=p.stdout.read(num(n));assert len(data)==num(n);return data
        assert exchange(b"\1"+u32(3))==b"\2"+u32(3)
        seq=0
        def req(t,args):
            global seq
            seq+=1
            a=exchange(bytes([t])+u32(seq)+args)
            assert a[1:5]==u32(seq)
            return a[0],a[5:]
        def status(t,args,code):
            typ,data=req(t,args);assert typ==101 and data[:4]==u32(code),(t,code,typ,data)
        def real(path):
            typ,data=req(16,s(path));assert typ==104 and data[:4]==u32(1)
            n=num(data[4:8]);return data[8:8+n]
        assert real(b".")==real(b"/")==b"/" and real(b"samples/")==b"/samples"
        for path in [b"/../",b"/samples/../x",b"/bad:name",b"/bad\\name",b"/A\0B",b"//",b"/a//b",b"/abc. ",b"/"+"x".encode()*101]:
            status(7,s(path),3)
        for t in [7,17]:
            assert req(t,s(b"/samples"))[0]==105
            status(t,s(b"/missing"),2)
        assert req(17,s(b"/samples/settings.bin"))[1][:12]==u32(13)+u64(70123)
        status(17,s(b"/")+b"x",5)
        for f in [0,2,3,4,8,16,32]:
            status(3,s(b"/samples/settings.bin")+u32(f)+u32(0),3)
        for t in [6,9,10,13,14,15,18,20]:status(t,s(b"/"),3)
        status(200,s(b"unsupported@example"),8)
        typ,hd=req(11,s(b"/samples"));assert typ==102
        typ,row=req(12,hd);assert typ==104 and b"settings.bin" in row
        status(12,hd,1);status(5,hd+u64(0)+u32(1),4);status(4,hd,0)
        typ,h=req(3,s(b"/samples/settings.bin")+u32(1)+u32(0));assert typ==102
        assert req(8,h)[0]==105
        status(4,hd,4);status(12,h,4)
        chunks=[]
        for off in [0,32768,65536]:
            typ,a=req(5,h+u64(off)+u32(131072));assert typ==103 and num(a[:4])==len(a[4:]);chunks.append(a[4:])
        expected=bytes(i%251 for i in range(70123))
        assert b"".join(chunks)==expected
        status(5,h+u64(70123)+u32(100),1);status(4,h,0)
        handles=[]
        for _ in range(8):
            typ,v=req(11,s(b"/"));assert typ==102;handles.append(v)
        status(11,s(b"/"),4)
        # Terminate with handles still open: fixture asserts reset closed every fd.
        print(f"PASS {seq} SFTP v3 requests; binary bytes={len(expected)} sha256={hashlib.sha256(expected).hexdigest()}")
    finally:
        p.stdin.close();p.stdout.close()
        assert p.wait(timeout=10)==0
    sftp=shutil.which("sftp")
    if sftp:
        # -D talks directly to the fixture over stdio; no sockets, host keys, or device.
        (d/"commands").write_text("pwd\nls /samples\nget /samples/settings.bin download.bin\nbye\n",encoding="ascii")
        import platform
        if os.name=="nt":
            # Win32-OpenSSH's -D uses forward-slash paths. Quote for spaces.
            cmd='"'+exe.as_posix()+'"'
        else:
            import shlex
            cmd=shlex.quote(str(exe))
        x=subprocess.run([sftp,"-b","commands","-D",cmd],cwd=d,capture_output=True,timeout=25)
        assert x.returncode==0,(x.returncode,x.stdout,x.stderr)
        assert (d/"download.bin").read_bytes()==expected
        print("PASS OpenSSH sftp -D: pwd, ls, get; 70,123 remote fixture bytes match")
    else:print("SKIP OpenSSH sftp -D (client absent)")
