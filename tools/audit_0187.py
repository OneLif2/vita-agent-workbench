"""Re-open exact build receipts and reject valid-ZIP feature removals; no Vita access."""
import argparse,hashlib,json,re,subprocess,sys,tempfile,zipfile
from pathlib import Path
from build_0187 import H,checked_release
import release_inputs_0187 as inputs
R=Path(__file__).resolve().parents[1]
E=R/'evidence'

def sha(b):return hashlib.sha256(b).hexdigest()
def pack(folder):
    argv=[sys.executable,'-B',str(R/'source/verify_package.py'),str(folder)]
    p=subprocess.run(argv,capture_output=True)
    return dict(argv=argv,rc=p.returncode,stdout=p.stdout.decode('utf8','replace'),stderr=p.stderr.decode('utf8','replace'))
def entries(raw):
    pairs=[s.split('  ',1) for s in raw.decode().splitlines()]
    d={n:h for h,n in pairs}
    assert len(d)==len(pairs) and all(re.fullmatch('[0-9a-f]{64}',h) for h in d.values())
    return d

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--jetson',required=True);a.add_argument('--pin-record',required=True);a=a.parse_args()
    assert re.fullmatch(r'jetson-0187-[0-9]{8}T[0-9]{12}Z\.json',a.jetson)
    frozen=inputs.frozen_files();checked_release(a.pin_record,frozen)
    jet=E/a.jetson;ops=json.loads(jet.read_bytes());assert len(ops)==6 and all(x['rc']==0 for x in ops)
    assert all(x['argv'][:-1]==H for x in ops[:5])
    dest=ops[0]['stdout'].strip();assert re.fullmatch(r'/home/pi/\.wb0187\.[a-zA-Z0-9]{8}',dest)
    rel='source/build/workbench_0187.vpk'
    assert [x['argv'][-1] for x in ops[:5]]==[
        'umask 077; mktemp -d /home/pi/.wb0187.XXXXXXXX',
        f'cd {dest} && tar xzf - && sha256sum --quiet -c INPUTS.sha256',
        f'cd {dest}/source && sh build-jetson.sh --check && sh build-jetson.sh build',
        f'cd {dest} && sha256sum --quiet -c INPUTS.sha256 && sha256sum {rel}',f'cat {dest}/{rel}']
    previous=(E/'PARENT-NATIVE-0187.inputs.sha256').read_bytes()
    actual=jet.with_suffix('.inputs.sha256').read_bytes()
    assert sha(previous)==inputs.PARENT_MANIFEST_SHA and actual==inputs.manifest(frozen)
    old,new=entries(previous),entries(actual)
    delta={k:dict(old=old.get(k),new=new.get(k)) for k in sorted(old.keys()|new.keys()) if old.get(k)!=new.get(k)}
    assert set(delta)==inputs.NATIVE_DELTA
    vp=R/'build/workbench_0187.vpk';parent=R.parent/'v1.85-r2/build/workbench_0186.vpk'
    digest=sha(vp.read_bytes());assert digest!=sha(parent.read_bytes())
    assert ops[3]['stdout'].split()==[digest,rel] and ops[4]['stdout_sha256']==digest and ops[4]['stdout'] is None
    assert ops[5]['argv'][1:-1]==['-B',str(R/'source/verify_package.py')] and digest in ops[5]['stdout']
    with zipfile.ZipFile(vp) as z,zipfile.ZipFile(parent) as p:
        members={n:sha(z.read(n)) for n in z.namelist()}
        assert z.read('workbench_payload.suprx')==p.read('workbench_payload.suprx')
    checks={'intact':pack(vp.parent)};assert checks['intact']['rc']==0
    with tempfile.TemporaryDirectory() as td:
        d=Path(td);q=d/vp.name;q.write_bytes(parent.read_bytes())
        checks['renamed_parent']=pack(d);assert checks['renamed_parent']['rc']!=0 and 'exact v1.86 core build tag mismatch' in checks['renamed_parent']['stderr']
        probes=[
            ('autoentry',b'PAIRED LISTENER AUTO ENTRY; UPDATE GRANT UNCHANGED','missing exact v1.86 paired autoentry feature'),
            ('wake',b'ERR close-wb wake-not-ready','missing 01.87 wake guard feature'),
            ('canary',inputs.CANARY_SHA.encode(),'wrong or missing exact 01.87 lifecycle canary approval'),
            ('signed',b'ERR r1-signed signature','missing exact v1.86 signed-update feature'),
            ('status',b'END wb-status','missing exact v1.86 device status feature'),
            ('signed_focus',b'R1 SIGNED FOCUS BRACKET END REFUSED','missing exact v1.86 signed-focus gate')]
        for name,needle,error in probes:
            with zipfile.ZipFile(vp) as source,zipfile.ZipFile(q,'w') as output:
                for info in source.infolist():
                    b=source.read(info)
                    if info.filename=='eboot.bin':
                        assert needle in b;b=b.replace(needle,b'?'*len(needle))
                    output.writestr(info,b)
            checks[name]=pack(d);assert checks[name]['rc']!=0 and error in checks[name]['stderr']
        for name,extra,error in [
            ('bootstrap',b'R1 STANDING BOOTSTRAP VERIFIED\0','may not enroll standing permission'),
            ('obsolete_square',b'SQUARE OPENS PAIRED SSH\0','obsolete paired-listener button gate remains')]:
            with zipfile.ZipFile(vp) as source,zipfile.ZipFile(q,'w') as output:
                for info in source.infolist():
                    b=source.read(info)+(extra if info.filename=='eboot.bin' else b'');output.writestr(info,b)
            checks[name]=pack(d);assert checks[name]['rc']!=0 and error in checks[name]['stderr']
    out=E/'NATIVE-DELTA.json'
    out.write_text(json.dumps(dict(scope='Offline host/Jetson only; no Vita deployment',candidate='01.87-live-autoentry',
        parent_manifest_sha256=sha(previous),candidate_manifest_sha256=sha(actual),native_inputs=len(new),changed_inputs=delta,
        registry_sha256=inputs.check_registry(),signer_sha256=inputs.public_profile(frozen),
        package=str(vp),bytes=vp.stat().st_size,sha256=digest,members=members,jetson_record=a.jetson,
        pin_record=a.pin_record,package_probes=checks),indent=2)+'\n',encoding='utf8')
    print(out,digest)
if __name__=='__main__':main()
