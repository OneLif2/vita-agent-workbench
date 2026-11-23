"""Actual stock OpenSSH direct SFTP client against the Workbench engine, no SSH or Vita connection."""
import hashlib, os, shutil, struct, subprocess, tempfile
from pathlib import Path
here=Path(__file__).resolve().parent
src=here.parents[1]/'source'
def tree(p):
    return {x.relative_to(p).as_posix(): None if x.is_dir() else hashlib.sha256(x.read_bytes()).hexdigest()
            for x in p.rglob('*')}

def test_wire(exe,env,root):
    be=lambda n:struct.pack('>I',n)
    s=lambda b:be(len(b))+b
    handle=be(0)+be(1)
    def request(kind,id,args=b''):
        msg=bytes([kind])+be(id)+args
        return be(len(msg))+msg
    def test(name,requests,expected):
        resp=subprocess.run([str(exe)],input=b''.join(requests),capture_output=True,env=env,check=True).stdout
        observed=[]
        while resp:
            n=int.from_bytes(resp[:4],'big');msg,resp=resp[4:4+n],resp[4+n:]
            observed.append((msg[0],int.from_bytes(msg[5:9],'big') if msg[0]==101 else None))
        assert observed==expected,(name,observed,expected)
    init=request(1,3)
    def op(p):return request(3,1,s(p.encode())+be(26)+be(4)+be(0o644))
    def write(off,data):return request(6,2,s(handle)+struct.pack('>Q',off)+s(data))
    close=request(4,3,s(handle)); prefix=[(2,None),(102,None)]
    test('channel cut before close',[init,op('/cut'),write(0,b'abc')],prefix+[(101,0)])
    test('out-of-order write poisons close',[init,op('/hole'),write(4,b'a'),close],prefix+[(101,4),(101,4)])
    test('oversize write poisons close',[init,op('/oversize'),write(0,b'a'*32769),close],prefix+[(101,4),(101,4)])
    test('final FSETSTAT length mismatch rejects CLOSE',[init,op('/mismatch'),write(0,b'abc'),request(10,9,s(handle)+be(1)+struct.pack('>Q',8)),close],prefix+[(101,0),(101,4),(101,4)])
    test('non-canonical path',[init,op('/../escape')],[(2,None),(101,3)])
    test('denied unlink',[init,request(13,8,s(b'/fresh'))],[(2,None),(101,3)])
    assert not any((root/n).exists() for n in ('cut','hole','oversize','mismatch'))
    print('PASS disconnect cleanup; offset/overlength reject and failed CLOSE; traversal and unlink denied')

with tempfile.TemporaryDirectory(prefix="wb-stock-scp-") as temp:
    d=Path(temp);remote=d/'remote';remote.mkdir()
    env={**os.environ,'WB_SCP_TEST_FS':str(remote),'LC_ALL':'C','LANG':'C'}
    exe=d/('fixture.exe' if os.name=='nt' else 'fixture')
    cc=shutil.which('gcc') or shutil.which('cc')
    subprocess.run([cc,'-std=c11','-Wall','-Wextra','-Werror','-DWB_TTY_FILE','-I',str(src),'-idirafter',str(here.parent/'stub'),str(here/'fixture.c'),
                    str(src/'wb_sha256.c'),str(src/'wb_sftp_vita.c'),str(src/'wb_path.c'),
                    str(src/'wb_sftp_frame.c'),str(src/'wb_sftp_ro.c'),'-o',str(exe)],check=True)
    scp=shutil.which('scp');assert scp
    def run(*args,ok=True):
        # scp -D is one program path (not a command line); never uses network/auth.
        x=subprocess.run([scp,'-D',str(exe),*args],cwd=d,env=env,capture_output=True,text=True,timeout=20)
        print('scp',' '.join(args),'exit',x.returncode,x.stderr.strip())
        assert (x.returncode==0)==ok,(x.stdout,x.stderr)
    (d/'one.bin').write_bytes(bytes(range(256))*300);(d/'two').write_bytes(b'\x00multi\r\n')
    run('one.bin','fixture:/fresh')
    run('fixture:/fresh','back.bin')
    assert (d/'back.bin').read_bytes()==(d/'one.bin').read_bytes()
    run('two','fixture:/fresh',ok=False)
    assert (remote/'fresh').read_bytes()==(d/'one.bin').read_bytes()
    (remote/'batch').mkdir()
    run('one.bin','two','fixture:/batch/')
    srcdir=d/'tree';(srcdir/'nest'/'deep').mkdir(parents=True);(srcdir/'empty').mkdir()
    (srcdir/'nest'/'deep'/'binary.bin').write_bytes(bytes(range(250))*654)
    (srcdir/'empty.bin').touch();(srcdir/'hello there.txt').write_bytes(b'two words')
    run('-r','tree','fixture:/')
    run('-r','fixture:/tree','roundtrip')
    assert tree(srcdir)==tree(remote/'tree')==tree(d/'roundtrip')
    assert tree(remote/'batch')=={'one.bin':hashlib.sha256((d/'one.bin').read_bytes()).hexdigest(),'two':hashlib.sha256((d/'two').read_bytes()).hexdigest()}
    print('PASS stock scp SFTP-mode single/multi-file and recursive push/pull; paths, empty dirs/files, binary SHA256, no overwrite',tree(srcdir))
    test_wire(exe,env,remote)
    env['WB_SCP_FAULT_SHA']='1';run('one.bin','fixture:/corrupt',ok=False)
    assert not (remote/'corrupt').exists()
    print('PASS forced stage-readback verification error reaches stock scp; destination absent')
