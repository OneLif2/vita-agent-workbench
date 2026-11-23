"""Offline re-open of release receipts and positive/negative package probes. No Vita access."""
import argparse, hashlib, json, re, subprocess, sys, tempfile, zipfile
from pathlib import Path
from build_0184_r2 import H, checked_release
import release_inputs_0184_r2 as inputs

R=Path(__file__).resolve().parents[1]
E=R/'evidence'
OLD=R.parent/'v1.84'
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
    if not re.fullmatch(r'jetson-0184-r2-[0-9]{8}T[0-9]{12}Z\.json',a.jetson):raise ValueError('expected named Jetson receipt')
    jet=E/a.jetson; frozen=inputs.frozen_files();checked_release(a.pin_record,frozen)
    previous=(OLD/'evidence/jetson-0184-20261122T183916748233Z.inputs.sha256').read_bytes()
    actual=jet.with_suffix('.inputs.sha256').read_bytes()
    old=manifest_entries(previous);new=manifest_entries(actual)
    assert actual==inputs.manifest(frozen) and sha(previous)==json.loads((E/'FORK-0184.json').read_bytes())['input_sha256']
    diff={k:dict(old=old.get(k),new=new.get(k)) for k in sorted(old.keys()|new.keys()) if old.get(k)!=new.get(k)}
    assert not any(k.startswith(('payload/','updater/')) for k in diff)
    assert old['tools/apps.txt']==new['tools/apps.txt']==inputs.APPROVAL_SHA and 'tools/apps.txt' not in diff
    # The r2 adapter is intentionally different; the underlying ticket
    # format, stage/workbench install and 5090 handoff boundaries are not.
    approval_boundary_paths=('source/wb_return_policy.h','source/wb_vita_install.c','source/wb_install.c')
    assert all(n in old and n not in diff for n in approval_boundary_paths), 'R1 ticket/approval or install backend changed'
    assert 'source/wb_return_vita.h' in diff
    assert (R/'tools/r1ctl.py').read_bytes()==(OLD/'tools/r1ctl.py').read_bytes(), '5090 handoff authority changed'
    operations=json.loads(jet.read_bytes())
    assert len(operations)==6 and all(op['rc']==0 for op in operations)
    assert all(op['argv'][:-1]==H for op in operations[:5])
    dest=operations[0]['stdout'].strip()
    assert re.fullmatch(r'/home/pi/\.wb0184r2\.[a-zA-Z0-9]{8}',dest)
    rel='source/build/workbench_0184.vpk'
    assert [op['argv'][-1] for op in operations[:5]]==[
        'umask 077; mktemp -d /home/pi/.wb0184r2.XXXXXXXX',
        f'cd {dest} && tar xzf - && sha256sum --quiet -c INPUTS.sha256',
        f'cd {dest}/source && sh build-jetson.sh --check && sh build-jetson.sh build',
        f'cd {dest} && sha256sum --quiet -c INPUTS.sha256 && sha256sum {rel}',
        f'cat {dest}/{rel}']
    vp=R/'build/workbench_0184.vpk'; previous_vpk=OLD/'build/workbench_0184.vpk'
    assert sha(previous_vpk.read_bytes())==json.loads((E/'FORK-0184.json').read_bytes())['base_vpk']
    digest=sha(vp.read_bytes())
    assert operations[3]['stdout'].split()==[digest,rel]
    assert operations[4]['stdout_sha256']==digest and operations[4]['stdout'] is None
    assert operations[5]['argv'][1:-1]==['-B',str(R/'source/verify_package.py')]
    assert f'sha256={digest}' in operations[5]['stdout']
    with zipfile.ZipFile(previous_vpk) as p, zipfile.ZipFile(vp) as c:
        assert p.read('workbench_payload.suprx')==c.read('workbench_payload.suprx')
        members={n:sha(c.read(n)) for n in c.namelist()}
    checks={'intact':pack(vp.parent)}
    with tempfile.TemporaryDirectory() as scratch:
        folder=Path(scratch); q=folder/vp.name
        q.write_bytes(previous_vpk.read_bytes());checks['stale_predecessor_renamed']=pack(folder)
        assert checks['stale_predecessor_renamed']['rc']!=0 and 'exact r2 core build tag mismatch' in checks['stale_predecessor_renamed']['stderr']
        needle=b'ERR close-wb wake-not-ready'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_feature']=pack(folder)
        assert checks['valid_zip_missing_feature']['rc']!=0 and 'missing 01.84 wake guard feature' in checks['valid_zip_missing_feature']['stderr']
        needle=inputs.CANARY_SHA.encode("ascii")
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_exact_canary']=pack(folder)
        assert checks['valid_zip_missing_exact_canary']['rc']!=0 and 'wrong or missing exact 01.84 lifecycle canary approval' in checks['valid_zip_missing_exact_canary']['stderr']
        needle=b'ERR r1-signed signature'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_signed_gate']=pack(folder)
        assert checks['valid_zip_missing_signed_gate']['rc']!=0 and 'missing exact r2 signed-update feature' in checks['valid_zip_missing_signed_gate']['stderr']
    assert checks['intact']['rc']==0 and digest in checks['intact']['stdout']
    target=E/'NATIVE-DELTA.json'
    target.write_text(json.dumps(dict(scope='Offline 5090/Jetson build only; no Vita, no stage, no installation',native_inputs=len(new),
        baseline_manifest_sha256=sha(previous),candidate_manifest_sha256=sha(actual),changed_inputs=diff,
        unchanged_approval_boundaries={n:old[n] for n in approval_boundary_paths},
        signer_sha256=inputs.public_profile(frozen),
        registry_sha256=inputs.APPROVAL_SHA,unchanged_registry_approval=dict(title=inputs.CANARY_TITLE,
            version='01.01',sha256=inputs.CANARY_SHA,launch_approved=False),
        package='build/workbench_0184.vpk',bytes=vp.stat().st_size,
        sha256=digest,members=members,jetson_record=a.jetson,jetson_record_sha256=sha(jet.read_bytes()),pin_record=a.pin_record,
        package_probes=checks),indent=2)+'\n',encoding='utf8')
    assert json.loads(target.read_bytes())['sha256']==sha(vp.read_bytes());print(target,digest)
if __name__=='__main__':main()
