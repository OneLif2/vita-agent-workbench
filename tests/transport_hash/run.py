"""Exercise production plan/inspect and SSH request framing offline, without connecting.
--baseline additionally records the same observations from a previous release.
"""
import argparse, contextlib, hashlib, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
VPK_SHA="f2609d1c89e88fd4b250019a0ca0160b97b2ad8b0028576310effac8fc990905"
EMPTY_SHA=hashlib.sha256(b"").hexdigest()
def extract(src, name):
    pat=re.compile(r"^static (?:bool|int) "+name+r"\(", re.M)
    m,=pat.finditer(src)
    return src[m.start():src.index("\n}",m.end())+2]

def run_tree(root,baseline,vpk):
    src=root/"source"
    sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    assert sha(vpk)==VPK_SHA
    cc=shutil.which("gcc"); assert cc
    with tempfile.TemporaryDirectory(prefix="wb32-hash-ssh-") as td:
        d=Path(td); target=d/("test.exe" if os.name=="nt" else "test")
        device=(src/"vita_ssh_status.c").read_text(); ssh=(src/"wb_ssh.c").read_text()
        parts=[extract(device,n) for n in ("do_plan","do_inspect")]
        parts.extend(extract(ssh,n) for n in (("finish_channel","run_command") if baseline else ("finish_channel","deny_exec","run_command")))
        (d/"handlers.inc").write_text("\n".join(parts),encoding="utf8")
        cmd=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror",*(() if baseline else ("-DHAS_HASH_SELFTEST",)),
             *(("-DWB_TEST_SFTP_EXEC_ONLY",) if "end_sftp(s);" in extract(ssh,"finish_channel") else ()),
             "-I",str(d),"-I",str(src),"-I",str(root/"tests/stub"),str(HERE/"fixture.c"),
             *(str(src/(n+".c")) for n in ("wb_sha256","wb_zip","wb_crc32","wb_inflate","wb_sfo","wb_out","wb_cmd","wb_err","wb_path","wb_str")),"-o",str(target)]
        x=subprocess.run(cmd,capture_output=True,text=True)
        if x.returncode: raise RuntimeError(x.stderr+x.stdout)
        records=[]
        empty=d/"empty";empty.write_bytes(b"")
        def case(label,op,line,file,required,forbidden=()):
            x=subprocess.run([str(target),op,line,str(file)],capture_output=True,text=True)
            assert x.returncode==0,x.stderr
            good=all(v in x.stdout for v in required) and all(v not in x.stdout for v in forbidden)
            records.append(dict(label=label,input=[op,line,file.name],matches_candidate=good,output=x.stdout,stderr=x.stderr,rc=x.returncode))
            if not baseline and not good:raise AssertionError(records[-1])
        for n in ('plan','inspect'):
            line=n+' ux0:/VITA-POC/input.vpk'
            case(n+'-positive','ok',line,vpk,['exit=0','sha256='+VPK_SHA])
            for mode,why in (('oom','nomem'),('io','io-error'),('partial','io-error')):
                case(n+'-'+mode,mode,line,vpk,['exit=1','ERR '+why+'\n'],['sha256='])
        case("empty-is-not-allocation-failure","ok","inspect ux0:/VITA-POC/empty.vpk",empty,['bytes=0 sha256='+EMPTY_SHA])
        for mode,reason,line in [('admission','admission','ver'),('foreground','foreground','ver'),('link','link','ver'),('ok','command','ver unexpected-argument')]:
            case('deny-'+reason,mode,line,vpk,['ack=1 nack=0 dispatch=0 exit=125 closed=1','ERR denied '+reason+'\n'],['ok safe query'])
        case('allowed-dispatch','ok','ver',vpk,['ack=1 nack=0 dispatch=1 exit=0 closed=1','ok safe query'])
        case('unauth-not-accepted','unauth','ver',vpk,['ack=0 nack=1 dispatch=0 exit=126'],['ERR denied','ok safe query'])
        case('ack-failed-no-dispatch','ackfail','ver',vpk,['return=0 ack=1 nack=0 dispatch=0 exit=-1'],['ERR denied','ok safe query'])
        if not baseline:case('device-fixed-hash-selftest','selftest','ver',vpk,['selftest=0'])
        return dict(scope='offline 5090 native C with Vita I/O and SSH-framing stubs',root=str(root.resolve()),compiled=[str(p) for p in cmd],case_count=len(records),candidate_expectations_met=sum(e['matches_candidate'] for e in records),cases=records)

def test_cli(root):
    sys.path.insert(0,str((root/"tools").resolve()));import wbctl as w
    cases=[(125,'ERR denied admission','denied'),(125,'ERR denied arbitrary','remote_error'),
           (125,'ERR denied command\nunrelated','remote_error'),(124,'TIMEOUT','timeout'),(255,'connect: Connection timed out','timeout'),
           (255,'Connection closed by remote host','disconnected'),(255,'Connection reset by peer','disconnected'),
           (255,'exec request failed on channel 0','transport_error'),(78,'ERR SSH host key verification failed','trust_error'),
           (255,'Permission denied (publickey).','authentication_failed'),(0,'ok','ok')]
    for rc,text,want in cases: assert w.exec_outcome(rc,text)['classification']==want
    def fake(cmd):
        assert cmd=='ver unexpected-argument'
        return 1,'ERR invalid or disallowed Workbench command/options'
    old=w.ssh
    try:
        w.ssh=fake; captured=io.StringIO()
        with contextlib.redirect_stdout(captured): rc=w.main(['--json','deny-check'])
        assert rc==0 and json.loads(captured.getvalue())['classification']=='terminal_command_denied' and json.loads(captured.getvalue())['adapter_rc']==1
    finally:w.ssh=old
    return dict(cli_cases=len(cases)+1,observed=json.loads(captured.getvalue()))

if __name__=="__main__":
    historical=HERE.parents[1]/'build/testapp-f2609d1c89e88fd4.vpk'
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,default=HERE.parents[1]);ap.add_argument('--baseline',type=Path);ap.add_argument('--vpk',type=Path,default=historical if historical.is_file() else HERE.parents[2]/'v1.31/build/testapp.vpk',help='immutable signed-off 01.00 fixture, never executed');ap.add_argument('--out',type=Path);a=ap.parse_args()
    data={}
    if a.baseline:data['baseline']=run_tree(a.baseline.resolve(),True,a.vpk.resolve())
    data.update(candidate=run_tree(a.root.resolve(),False,a.vpk.resolve()),classification=test_cli(a.root))
    if a.out:a.out.write_text(json.dumps(data,indent=2)+'\n',encoding='utf8')
    for k,v in data.items():print(k,{n:v[n] for n in ('case_count','candidate_expectations_met','cli_cases') if n in v})
