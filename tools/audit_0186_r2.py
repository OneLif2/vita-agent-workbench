"""Offline re-open of release receipts and positive/negative package probes. No Vita access."""
import argparse, hashlib, json, re, subprocess, sys, tempfile, zipfile
from pathlib import Path
from build_0186_r2 import H, checked_release
import release_inputs_0186_r2 as inputs

R=Path(__file__).resolve().parents[1]
E=R/'evidence'
OLD=R.parent/'v1.85'
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
    if not re.fullmatch(r'jetson-0186-r2-[0-9]{8}T[0-9]{12}Z\.json',a.jetson):raise ValueError('expected named Jetson receipt')
    jet=E/a.jetson; frozen=inputs.frozen_files();checked_release(a.pin_record,frozen)
    previous=(OLD/'evidence/jetson-0185-20261122T193538788006Z.inputs.sha256').read_bytes()
    actual=jet.with_suffix('.inputs.sha256').read_bytes()
    old=manifest_entries(previous);new=manifest_entries(actual)
    assert actual==inputs.manifest(frozen) and sha(previous)==json.loads((E/'FORK-0185.json').read_bytes())['input_sha256']
    diff={k:dict(old=old.get(k),new=new.get(k)) for k in sorted(old.keys()|new.keys()) if old.get(k)!=new.get(k)}
    release_only={'source/build.sh','source/wb_ver.h','source/verify_package.py'}
    # Frozen allowlist: no status, updater, bootstrap or signed-policy drift.
    signed_focus_only={'source/wb_return_vita.h','source/wb_standing_vita.h',
                       'source/vita_ssh_status.c','source/wb_signed_focus.h'}
    assert set(diff)==release_only | signed_focus_only, 'unexpected native source drift: '+repr(sorted(diff))
    assert diff['source/wb_signed_focus.h']['old'] is None and diff['source/wb_signed_focus.h']['new']
    assert b'-DWB_STANDING_BOOTSTRAP=0 ' in frozen['source/build.sh'] and b'WB_STANDING_BOOTSTRAP=1' not in frozen['source/build.sh']
    assert old['tools/apps.txt']==new['tools/apps.txt']==inputs.APPROVAL_SHA and 'tools/apps.txt' not in diff
    immutable_guard_paths=('source/focus_guard.h','source/wb_return_policy.h',
                           'source/wb_vita_install.c','source/wb_install.c',
                           'source/wb_standing_provision.h','source/wb_standing_verify.h',
                           'source/wb_standing_message.h','source/wb_status_vita.h',
                           'source/wb_cmd.c','source/wb_cmd.h','source/wb_shell.c',
                           'updater/main.c','payload/payload_main.c')
    assert all(n in old and n not in diff for n in immutable_guard_paths), 'unchanged guard, updater or status source drifted'
    immutable_host_paths=('tools/r1ctl.py','tools/status_client.py','tools/wbctl.py',
                          'tools/auto_apply_staged.py','tools/auto_update_authorize.py',
                          'tools/stage_review.py')
    assert all((R/n).read_bytes()==(OLD/n).read_bytes() for n in immutable_host_paths), 'host status or update authority changed'
    assert (R/'evidence/STANDING-PUBLIC-PROFILE.json').read_bytes()==(OLD/'evidence/STANDING-PUBLIC-PROFILE.json').read_bytes()
    operations=json.loads(jet.read_bytes())
    assert len(operations)==6 and all(op['rc']==0 for op in operations)
    assert all(op['argv'][:-1]==H for op in operations[:5])
    dest=operations[0]['stdout'].strip()
    assert re.fullmatch(r'/home/pi/\.wb0186-r2\.[a-zA-Z0-9]{8}',dest)
    rel='source/build/workbench_0186.vpk'
    assert [op['argv'][-1] for op in operations[:5]]==[
        'umask 077; mktemp -d /home/pi/.wb0186-r2.XXXXXXXX',
        f'cd {dest} && tar xzf - && sha256sum --quiet -c INPUTS.sha256',
        f'cd {dest}/source && sh build-jetson.sh --check && sh build-jetson.sh build',
        f'cd {dest} && sha256sum --quiet -c INPUTS.sha256 && sha256sum {rel}',
        f'cat {dest}/{rel}']
    vp=R/'build/workbench_0186.vpk'; previous_vpk=OLD/'build/workbench_0186.vpk'
    assert sha(previous_vpk.read_bytes())==json.loads((E/'FORK-0185.json').read_bytes())['base_vpk']
    digest=sha(vp.read_bytes())
    assert digest!=sha(previous_vpk.read_bytes()), 'same-version r2 must not be the stale artifact'
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
        assert checks['stale_predecessor_renamed']['rc']!=0 and 'exact v1.85-r2 core build tag mismatch' in checks['stale_predecessor_renamed']['stderr']
        needle=b'ERR close-wb wake-not-ready'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_feature']=pack(folder)
        assert checks['valid_zip_missing_feature']['rc']!=0 and 'missing 01.86 wake guard feature' in checks['valid_zip_missing_feature']['stderr']
        needle=inputs.CANARY_SHA.encode("ascii")
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_exact_canary']=pack(folder)
        assert checks['valid_zip_missing_exact_canary']['rc']!=0 and 'wrong or missing exact 01.86 lifecycle canary approval' in checks['valid_zip_missing_exact_canary']['stderr']
        needle=b'ERR r1-signed signature'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_signed_gate']=pack(folder)
        assert checks['valid_zip_missing_signed_gate']['rc']!=0 and 'missing exact v1.85-r2 signed-update feature' in checks['valid_zip_missing_signed_gate']['stderr']
        needle=b'END wb-status'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_status_feature']=pack(folder)
        assert checks['valid_zip_missing_status_feature']['rc']!=0 and 'missing exact v1.85-r2 device status feature' in checks['valid_zip_missing_status_feature']['stderr']
        needle=b'R1 SIGNED FOCUS BRACKET END REFUSED'
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':
                    assert needle in data
                    data=data.replace(needle,b'?'*len(needle))
                output.writestr(info,data)
        checks['valid_zip_missing_signed_focus']=pack(folder)
        assert checks['valid_zip_missing_signed_focus']['rc']!=0 and 'missing exact v1.85-r2 signed-focus gate' in checks['valid_zip_missing_signed_focus']['stderr']
        with zipfile.ZipFile(vp) as source, zipfile.ZipFile(q,'w') as output:
            for info in source.infolist():
                data=source.read(info)
                if info.filename=='eboot.bin':data+=b'R1 STANDING BOOTSTRAP VERIFIED\0'
                output.writestr(info,data)
        checks['valid_zip_unexpected_bootstrap']=pack(folder)
        assert checks['valid_zip_unexpected_bootstrap']['rc']!=0 and 'may not enroll standing permission' in checks['valid_zip_unexpected_bootstrap']['stderr']
    assert checks['intact']['rc']==0 and digest in checks['intact']['stdout']
    target=E/'NATIVE-DELTA.json'
    target.write_text(json.dumps(dict(scope='Offline 5090/Jetson build only; no Vita, no stage, no installation',native_inputs=len(new),
        baseline_manifest_sha256=sha(previous),candidate_manifest_sha256=sha(actual),changed_inputs=diff,
        unchanged_approval_boundaries={n:old[n] for n in immutable_guard_paths},
        unchanged_host_authority={n:sha((R/n).read_bytes()) for n in immutable_host_paths},
        signer_sha256=inputs.public_profile(frozen),
        registry_sha256=inputs.APPROVAL_SHA,unchanged_registry_approval=dict(title=inputs.CANARY_TITLE,
            version='01.01',sha256=inputs.CANARY_SHA,launch_approved=False),
        package='build/workbench_0186.vpk',bytes=vp.stat().st_size,
        sha256=digest,members=members,jetson_record=a.jetson,jetson_record_sha256=sha(jet.read_bytes()),pin_record=a.pin_record,
        package_probes=checks),indent=2)+'\n',encoding='utf8')
    assert json.loads(target.read_bytes())['sha256']==sha(vp.read_bytes());print(target,digest)
if __name__=='__main__':main()
