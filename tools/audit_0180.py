"""Offline re-open of release receipts and positive/negative package probes. No Vita access."""
import argparse, hashlib, json, re, subprocess, sys, tempfile, zipfile
from pathlib import Path
from build_0180 import checked_release
import release_inputs_0180 as inputs

R=Path(__file__).resolve().parents[1]
E=R/'evidence'
OLD=R.parent/'v1.79'
def sha(data): return hashlib.sha256(data).hexdigest()
def pack(directory):
    args=[sys.executable,'-B',str(R/'source/verify_package.py'),str(directory)]
    run=subprocess.run(args,capture_output=True)
    return dict(argv=args,rc=run.returncode,stdout=run.stdout.decode('utf8','replace'),stderr=run.stderr.decode('utf8','replace'))
def manifest_entries(raw):
    pairs=[line.split('  ',1) for line in raw.decode('utf8').splitlines()]
    result={path:digest for digest,path in pairs}
    assert len(pairs)==len(result) and all(re.fullmatch('[0-9a-f]{64}',v) for v in result.values())
    return result
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--jetson',required=True);ap.add_argument('--pin-record',required=True)
    a=ap.parse_args()
    if not re.fullmatch(r'jetson-0180-[0-9]{8}T[0-9]{12}Z\.json',a.jetson):raise ValueError('expected named Jetson receipt')
    jet=E/a.jetson; frozen=inputs.frozen_files();checked_release(a.pin_record,frozen)
    previous=(OLD/'evidence/jetson-0179-20261122T145932975884Z.inputs.sha256').read_bytes()
    actual=jet.with_suffix('.inputs.sha256').read_bytes()
    old=manifest_entries(previous);new=manifest_entries(actual)
    assert actual==inputs.manifest(frozen) and sha(previous)==json.loads((E/'FORK-0179.json').read_bytes())['frozen_sha256']
    diff={k:dict(old=old.get(k),new=new.get(k)) for k in sorted(old.keys()|new.keys()) if old.get(k)!=new.get(k)}
    assert not any(k.startswith(('payload/','updater/')) for k in diff) and 'tools/apps.txt' not in diff
    operations=json.loads(jet.read_bytes()); assert operations and all(op['rc']==0 for op in operations)
    vp=R/'build/workbench_0180.vpk'; previous_vpk=OLD/'build/workbench_0179.vpk'
    assert sha(previous_vpk.read_bytes())==json.loads((E/'FORK-0179.json').read_bytes())['baseline_vpk_sha256']
    digest=sha(vp.read_bytes())
    assert any(op['stdout_sha256']==digest and op['stdout'] is None for op in operations)
    with zipfile.ZipFile(previous_vpk) as p, zipfile.ZipFile(vp) as c:
        assert p.read('workbench_payload.suprx')==c.read('workbench_payload.suprx')
        members={n:sha(c.read(n)) for n in c.namelist()}
    checks={'intact':pack(vp.parent)}
    with tempfile.TemporaryDirectory() as scratch:
        folder=Path(scratch); q=folder/vp.name
        q.write_bytes(previous_vpk.read_bytes());checks['stale_predecessor_renamed']=pack(folder)
        assert checks['stale_predecessor_renamed']['rc']!=0 and 'core build-tag mismatch' in checks['stale_predecessor_renamed']['stderr']
        needle=b'ERR crash-index no-pty'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_feature']=pack(folder)
        assert checks['valid_zip_missing_feature']['rc']!=0 and 'missing 01.80 crash metadata feature' in checks['valid_zip_missing_feature']['stderr']
    assert checks['intact']['rc']==0 and digest in checks['intact']['stdout']
    target=E/'NATIVE-DELTA.json'
    target.write_text(json.dumps(dict(scope='Offline 5090/Jetson build only; no Vita, no stage, no installation',native_inputs=len(new),
        baseline_manifest_sha256=sha(previous),candidate_manifest_sha256=sha(actual),changed_inputs=diff,
        registry_sha256=inputs.APPROVAL_SHA,package='build/workbench_0180.vpk',bytes=vp.stat().st_size,
        sha256=digest,members=members,jetson_record=a.jetson,jetson_record_sha256=sha(jet.read_bytes()),pin_record=a.pin_record,
        package_probes=checks),indent=2)+'\n',encoding='utf8')
    assert json.loads(target.read_bytes())['sha256']==sha(vp.read_bytes());print(target,digest)
if __name__=='__main__':main()
