"""Supplement the primary shell roles with an exact native GET policy transaction."""
from pathlib import Path
import datetime,difflib,hashlib,json,os,subprocess,tempfile
import run

D=Path(__file__).resolve().parent;R=D/'transaction';S=run.S
def sha(b):return hashlib.sha256(b).hexdigest()
def capture(cmd,cwd=None):
    p=subprocess.run([str(x) for x in cmd],cwd=cwd,capture_output=True,text=True)
    return dict(command=[str(x) for x in cmd],cwd=str(cwd or Path.cwd()),exit=p.returncode,stdout=p.stdout,stderr=p.stderr)
def main():
    original=(R/'BASELINE.inc').read_bytes();target=S/'wb_tty_vita.inc';modified=target.read_bytes()
    assert sha(original)=='30d22f52ff04255ce753f0dea43fc3f6e80c9b748e00001c9ec6107c867727aa'
    parent=S.parents[1]/'v1.88/source/wb_tty_vita.inc';assert parent.read_bytes()==original
    assert modified==original.replace(b'"shot.bmp","testapp/result.txt"',b'"shot.bmp","testapp/result.txt","wake-probe/result.bin"')
    (R/'MODIFIED_FILE.inc').write_bytes(modified)
    patch=''.join(difflib.unified_diff(original.decode().splitlines(True),modified.decode().splitlines(True),fromfile='a/wb_tty_vita.inc',tofile='b/wb_tty_vita.inc'))
    (R/'DIFF_FILE.patch').write_bytes(patch.encode())
    rollback='''#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo "usage: ROLLBACK.sh target-copy" >&2; exit 64; }
base=$(CDPATH= cd "$(dirname "$0")" && pwd)
cp "$base/BASELINE.inc" "$1"
'''
    (R/'ROLLBACK.sh').write_bytes(rollback.encode());(R/'ROLLBACK.sh').chmod(0o755)
    shell=Path(r'C:\Program Files\Git\bin\bash.exe') if os.name=='nt' else Path('/bin/sh')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='wb-result-get-policy-') as temp:
        t=Path(temp)
        for label,adapter in [('BASELINE',R/'BASELINE.inc'),('MODIFIED',R/'MODIFIED_FILE.inc')]:
            result=capture([run.build(t/label,adapter),'get-result']);result['label']=label;rows.append(result)
            assert result['exit']==0 and not result['stderr'],result
        restored=t/'restored.inc';restored.write_bytes(modified)
        result=capture([shell,(R/'ROLLBACK.sh').as_posix(),restored.as_posix()]);result['label']='ROLLBACK_SCRIPT';rows.append(result)
        assert result['exit']==0 and restored.read_bytes()==original,result
        result=capture([run.build(t/'ROLLBACK',restored),'get-result']);result['label']='ROLLBACK';rows.append(result)
        assert result['exit']==0 and result['stdout']==rows[0]['stdout'] and not result['stderr'],result
        p=t/'patch';p.mkdir();(p/'wb_tty_vita.inc').write_bytes(original)
        result=capture(['git','-c','core.autocrlf=false','apply','--whitespace=nowarn',R/'DIFF_FILE.patch'],p);result['label']='PATCH_RECONSTRUCTION';rows.append(result)
        assert result['exit']==0 and (p/'wb_tty_vita.inc').read_bytes()==modified,result
        result=capture([run.build(t/'FULL')]);result['label']='FULL_ADAPTER_REGRESSION';rows.append(result)
        assert result['exit']==0 and not result['stderr'] and '13 job/private/sibling/traversal negatives x5 operations' in result['stdout'],result
        result=capture([shell,'-n',(R/'ROLLBACK.sh').as_posix()]);result['label']='PORTABLE_SH_PARSE';rows.append(result);assert result['exit']==0
    assert rows[0]['stdout']=='DENIED error=path-denied writes=0 removes=0\n'
    assert 'GET bytes=256 read=256 sha256=' in rows[1]['stdout'] and rows[1]['stdout'].endswith('readonly=1 writes=0 removes=0\n')
    assert target.read_bytes()==modified and parent.read_bytes()==original
    (R/'MODIFIED_FILE.inc').write_bytes(modified)
    roles={k:str(R/v) for k,v in {'MODIFIED_FILE':'MODIFIED_FILE.inc','DIFF_FILE':'DIFF_FILE.patch','VERIFICATION':'VERIFICATION.txt','ROLLBACK':'ROLLBACK.sh'}.items()}
    evidence=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='Supplementary native exact-public-result GET allowlist; host memory files, no Vita/SFTP/UI/receiver/close authority',
        changed_symbol='tty_diag exact read-only leaf wake-probe/result.bin only',input='get-result',protocol_contract='Native positive uses WP_RESULT_PATH directly from shared wake_probe_protocol.h, so path drift fails the real production-policy test.',
        original_path=str(parent),target=str(target),original_sha256=sha(original),modified_sha256=sha(modified),restored_sha256=sha(original),
        full_regression='Existing upload/tree/digest/no-clobber checks unchanged; 79 additional assert executions include 13 denied paths x 5 read/write/stream/mkdir/tree operations; readonly write attempt and GET finish/abort cannot mutate/unlink.',
        commands=rows,roles=roles,primary_role_verification=str(D.parent/'wake_probe/transaction/VERIFICATION.txt'))
    (R/'VERIFICATION.txt').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf8')
    for role,path in roles.items():
        p=Path(path);b=p.read_bytes();assert b;print(role,path,len(b),sha(b))
    primary=D.parent/'wake_probe/transaction/VERIFICATION.txt'
    prior=primary.read_bytes();record=json.loads(prior)
    archive=primary.parent/'history'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'-tty-result-get-supplement');archive.mkdir(parents=True)
    (archive/'VERIFICATION.txt').write_bytes(prior)
    record.setdefault('supplemental_transactions',[]).append(dict(scope='Exact native result GET integration correction; existing shell roles and their three-state evidence unchanged.',verification=str(R/'VERIFICATION.txt'),sha256=sha((R/'VERIFICATION.txt').read_bytes()),prior_primary_verification=str(archive/'VERIFICATION.txt'),prior_sha256=sha(prior),roles=roles))
    primary.write_text(json.dumps(record,indent=2,ensure_ascii=False)+'\n',encoding='utf8');json.loads(primary.read_bytes())
    for row in rows[:4]:print(row['label'],json.dumps({k:row[k] for k in ['exit','stdout','stderr']}))
    print('PASS native exact shared-result GET; denied -> readonly256 -> denied rollback; prior primary roles preserved and supplemented')
if __name__=='__main__':main()
