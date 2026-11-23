"""Supplemental native header transaction: capture before private R1 I/O."""
from pathlib import Path
import hashlib,difflib,json,subprocess,sys,uuid
R=Path(__file__).resolve().parents[2];P=R.parent/'v1.86';D=Path(__file__).resolve().parent/'header-transaction';D.mkdir(exist_ok=False)
a=(P/'source/wb_return_vita.h').read_bytes();b=(R/'source/wb_return_vita.h').read_bytes();assert a!=b
(D/'BASELINE.h').write_bytes(a);(D/'MODIFIED_FILE.h').write_bytes(b)
(D/'DIFF_FILE.patch').write_text(''.join(difflib.unified_diff(a.decode().splitlines(True),b.decode().splitlines(True),fromfile='a/wb_return_vita.h',tofile='b/wb_return_vita.h')),encoding='utf-8',newline='\n')
(D/'ROLLBACK.sh').write_text('#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nd=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\ncp "$d/BASELINE.h" "$1"\ncmp "$d/BASELINE.h" "$1"\nprintf "%s\\n" "restored pristine R1 header"\n',encoding='utf-8',newline='\n')
W=R/'evidence'/('handoff-header-'+uuid.uuid4().hex[:12]);W.mkdir();target=W/'wb_return_vita.h';target.write_bytes(a)
j={'scope':'actual main APPLY_RETURN with actual R1 header; SDK/storage/crypto stubs, no Vita','symbol':'r1_apply signed begin before private savedata read; unchanged subsequent nonce/receipt/pin checks','input':'private-read-2s; coherent2s on private R1 reads','parent':str(P/'source/wb_return_vita.h'),'original_sha256':hashlib.sha256(a).hexdigest(),'modified_sha256':hashlib.sha256(b).hexdigest(),'main_sha256':hashlib.sha256((R/'source/vita_ssh_status.c').read_bytes()).hexdigest(),'steps':[]}
def run(label,args,cwd=W):
 o=subprocess.run([str(x) for x in args],cwd=cwd,capture_output=True,text=True);j['steps'].append(dict(label=label,argv=[str(x) for x in args],cwd=str(cwd),stdout=o.stdout,stderr=o.stderr,exit=o.returncode));print(label,o.returncode,repr(o.stdout),repr(o.stderr));assert o.returncode==0 and not o.stderr
try:
 test=R/'tests/full_handoff/run.py'
 run('BASELINE',[sys.executable,'-B',test,'private-read-2s','--return-header',target,'--expect','refuse'])
 run('apply',['git','-c','core.autocrlf=false','apply','--binary',D/'DIFF_FILE.patch']);assert target.read_bytes()==b
 run('MODIFIED',[sys.executable,'-B',test,'private-read-2s','--return-header',target,'--expect','pass'])
 restored=W/'restored';restored.mkdir();copy=restored/'wb_return_vita.h';copy.write_bytes(b)
 run('ROLLBACK EXECUTE',[r'C:\Program Files\Git\bin\sh.exe',str(D/'ROLLBACK.sh').replace('\\','/'),str(copy).replace('\\','/')]);assert copy.read_bytes()==a
 j['restored_sha256']=hashlib.sha256(copy.read_bytes()).hexdigest()
 run('ROLLBACK',[sys.executable,'-B',test,'private-read-2s','--return-header',copy,'--expect','refuse'])
 run('reapply',['git','-c','core.autocrlf=false','apply','--binary',D/'DIFF_FILE.patch'],restored);assert copy.read_bytes()==b
 run('REAPPLIED',[sys.executable,'-B',test,'private-read-2s','--return-header',copy,'--expect','pass'])
 assert (P/'source/wb_return_vita.h').read_bytes()==a and (R/'source/wb_return_vita.h').read_bytes()==b
 j['hashes']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [D/'BASELINE.h',D/'MODIFIED_FILE.h',D/'DIFF_FILE.patch',D/'ROLLBACK.sh']}
finally:(D/'VERIFICATION.txt').write_text(json.dumps(j,indent=2)+'\n',encoding='utf-8')
for n in ('MODIFIED_FILE.h','DIFF_FILE.patch','VERIFICATION.txt','ROLLBACK.sh'):
 p=D/n;print('REOPENED',p,len(p.read_bytes()),hashlib.sha256(p.read_bytes()).hexdigest())
