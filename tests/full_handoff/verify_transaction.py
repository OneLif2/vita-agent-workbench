"""Rebuild/revert the actual main handoff change on separate host-only copies."""
from pathlib import Path
import difflib,hashlib,json,subprocess,sys,datetime,uuid
R=Path(__file__).resolve().parents[2];P=R.parent/'v1.86'
D=Path(__file__).resolve().parent/'transaction'
archive=D.with_name('transaction-stat-review-before-eol') if sys.argv[1:]==['--refresh-eol'] else D.with_name('transaction-before-stat-review')
regression=D.with_name('transaction-before-stat-review')
if D.exists():
    assert sys.argv[1:] in (['--refresh-reviewed'],['--refresh-eol']) and archive.is_dir(),'do not overwrite an existing transaction'
    for f in D.iterdir():
        if f.is_file():assert f.read_bytes()==(archive/f.name).read_bytes(),'pre-review role changed after archive'
else:D.mkdir()
a=(P/'source/vita_ssh_status.c').read_bytes();b=(R/'source/vita_ssh_status.c').read_bytes()
assert a!=b and b''.join(a.split())!=b''.join(b.split())
(D/'BASELINE.c').write_bytes(a);(D/'MODIFIED_FILE.c').write_bytes(b)
(D/'DIFF_FILE.patch').write_text(''.join(difflib.unified_diff(a.decode().splitlines(True),b.decode().splitlines(True),fromfile='a/vita_ssh_status.c',tofile='b/vita_ssh_status.c')),encoding='utf-8',newline='\n')
(D/'ROLLBACK.sh').write_text('#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nd=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\ncp "$d/BASELINE.c" "$1"\ncmp "$d/BASELINE.c" "$1"\nprintf "%s\\n" "restored pristine main handoff"\n',encoding='utf-8',newline='\n')
W=R/'evidence'/('handoff-transaction-'+uuid.uuid4().hex[:12]);W.mkdir();target=W/'vita_ssh_status.c';target.write_bytes(a)
j={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'actual main APPLY_RETURN + actual R1/focus; SDK/storage/crypto stubs; no network/Vita','symbol':'signed whole handoff bracket and total transaction limit','input':'intergate-2s; helper step coherent2s; exact existing signed ticket','parent':str(P/'source/vita_ssh_status.c'),'original_sha256':hashlib.sha256(a).hexdigest(),'candidate_sha256':hashlib.sha256(b).hexdigest(),'pre_review_archive':str(archive),'steps':[],'prior_fixture_errors':[{'exit':1,'source':'first full_handoff fixture build','diagnostic':'sceIo function prototypes/static conflicted with SDK headers; matched actual declared SDK types/linkage'},{'exit':3221226505,'source':'full-handoff-debug/prior-fixture-error.json','diagnostic':'wrong_run fixture assigned already-active newrun; changed to distinct valid fixture run'},{'exit':3221226505,'source':'full-handoff-debug-reset/prior-fixture-error.json','diagnostic':'late fault fixture flags leaked into next bootstrap; reset before enrollment'},{'exit':1,'source':'physical-route coverage fixture compile','diagnostic':'r1_issue_local takes one argument; corrected fixture typo'}]}
def run(label,args,cwd=W):
 o=subprocess.run([str(x) for x in args],cwd=cwd,capture_output=True,text=True)
 j['steps'].append(dict(label=label,argv=[str(x) for x in args],cwd=str(cwd),stdout=o.stdout,stderr=o.stderr,exit=o.returncode));print(label,o.returncode,repr(o.stdout),repr(o.stderr))
 assert o.returncode==0 and not o.stderr,label
try:
 test=R/'tests/full_handoff/run.py'
 if regression.exists():run('BEFORE_REVIEW_STAT_REGRESSION',[sys.executable,'-B',test,'teststat-2s','--source',regression/'MODIFIED_FILE.c','--expect','refuse'])
 run('BASELINE',[sys.executable,'-B',test,'intergate-2s','--source',target,'--expect','refuse'])
 run('BASELINE_STAT',[sys.executable,'-B',test,'teststat-2s','--source',target,'--expect','refuse'])
 run('apply',['git','-c','core.autocrlf=false','apply','--binary',D/'DIFF_FILE.patch']);assert target.read_bytes()==b
 run('MODIFIED',[sys.executable,'-B',test,'intergate-2s','--source',target,'--expect','pass'])
 run('MODIFIED_STAT',[sys.executable,'-B',test,'teststat-2s','--source',target,'--expect','pass'])
 restored=W/'restored';restored.mkdir();c=restored/'vita_ssh_status.c';c.write_bytes(b)
 run('ROLLBACK EXECUTE',[r'C:\Program Files\Git\bin\sh.exe',str(D/'ROLLBACK.sh').replace('\\','/'),str(c).replace('\\','/')]);assert c.read_bytes()==a
 j['restored_sha256']=hashlib.sha256(c.read_bytes()).hexdigest()
 run('ROLLBACK',[sys.executable,'-B',test,'intergate-2s','--source',c,'--expect','refuse'])
 run('ROLLBACK_STAT',[sys.executable,'-B',test,'teststat-2s','--source',c,'--expect','refuse'])
 run('reapply',['git','-c','core.autocrlf=false','apply','--binary',D/'DIFF_FILE.patch'],restored);assert c.read_bytes()==b
 run('REAPPLIED',[sys.executable,'-B',test,'intergate-2s','--source',c,'--expect','pass'])
 run('REAPPLIED_STAT',[sys.executable,'-B',test,'teststat-2s','--source',c,'--expect','pass'])
 run('ALL_MAIN_HANDOFF_CASES',[sys.executable,'-B',test])
 assert (P/'source/vita_ssh_status.c').read_bytes()==a and (R/'source/vita_ssh_status.c').read_bytes()==b
 j['hashes']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [D/'BASELINE.c',D/'MODIFIED_FILE.c',D/'DIFF_FILE.patch',D/'ROLLBACK.sh']}
finally:(D/'VERIFICATION.txt').write_text(json.dumps(j,indent=2)+'\n',encoding='utf-8')
for n in ('MODIFIED_FILE.c','DIFF_FILE.patch','VERIFICATION.txt','ROLLBACK.sh'):
 p=D/n;print('REOPENED',str(p),len(p.read_bytes()),hashlib.sha256(p.read_bytes()).hexdigest())
