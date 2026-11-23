"""Build the finite01.02 diagnostic in fresh pinned Jetson space. Never control Vita."""
from pathlib import Path
import argparse,datetime,hashlib,io,json,re,subprocess,sys,tarfile,tempfile,zipfile,struct
R=Path(__file__).resolve().parents[1];D=R/'wake-probe'
H=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=8','pi']
def sha(b):return hashlib.sha256(b).hexdigest()
def frozen():
    return {p.relative_to(R).as_posix():p.read_bytes() for p in sorted(D.rglob('*'))
            if p.is_file() and p.suffix in ('.c','.h','.py','.sh','.inc') and
            not {'build','evidence','transaction','__pycache__'}.intersection(p.relative_to(D).parts)}
def manifest(files):return ''.join(sha(b)+'  '+n+'\n' for n,b in sorted(files.items())).encode()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-digest');ap.add_argument('--cases',type=int,default=34);ap.add_argument('--describe',action='store_true');a=ap.parse_args()
    files=frozen();identity=sha(manifest(files))
    if a.describe:print(json.dumps(dict(sha256=identity,files={k:sha(v) for k,v in files.items()}),indent=2));return
    if not a.source_digest or identity!=a.source_digest:raise ValueError('probe sources are not the explicitly frozen identity')
    if list((D/'build').glob('*.vpk')):raise ValueError('immutable probe artifact already exists; do not rebuild')
    now=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');out=D/'evidence'/('jetson-0102-'+now+'.json');out.parent.mkdir(exist_ok=True)
    report={'scope':'Host/fresh pinned Jetson diagnostic build only; no Vita/App lifecycle acceptance','source_before':identity,'source_files':{k:sha(v) for k,v in files.items()},'commands':[],'passed':False}
    def call(label,argv,data=None,binary=False,expected=0):
        try:p=subprocess.run(argv,input=data,capture_output=True,timeout=300,cwd=R)
        except subprocess.TimeoutExpired as exc:
            report['commands'].append(dict(label=label,argv=argv,exit=124,stdout=(exc.stdout or b'').decode('utf8','replace'),stderr=(exc.stderr or b'').decode('utf8','replace'),error=str(exc)));raise
        row=dict(label=label,argv=argv,exit=p.returncode,stdout=None if binary else p.stdout.decode('utf8','replace'),stdout_sha256=sha(p.stdout),stderr=p.stderr.decode('utf8','replace'));report['commands'].append(row)
        if p.returncode!=expected:raise RuntimeError(row)
        return p.stdout
    try:
        call('host-native-tests',[sys.executable,'-B',str(D/'tests/run.py')])
        host=json.loads((D/'evidence/HOST-TESTS.json').read_bytes());assert host['passed'] and host['case_count']==a.cases
        assert sha(manifest(frozen()))==identity
        remote=call('fresh-directory',H+['umask 077; mktemp -d /home/pi/.wb-wake-probe0190.XXXXXXXX']).decode().strip();assert re.fullmatch('/home/pi/\\.wb-wake-probe0190\\.[A-Za-z0-9]{8}',remote)
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as tar:
            for n,b in [*files.items(),('INPUTS.sha256',manifest(files))]:
                ti=tarfile.TarInfo(n);ti.size=len(b);ti.mode=0o700 if n.endswith('.sh') else 0o600;tar.addfile(ti,io.BytesIO(b))
        call('upload-frozen-inputs',H+[f'cd {remote} && tar xzf - && sha256sum --quiet -c INPUTS.sha256'],buf.getvalue())
        call('cross-build',H+[f'cd {remote}/wake-probe/sources && sh build.sh && cd ../.. && sha256sum --quiet -c INPUTS.sha256'])
        rel='wake-probe/sources/out/wake-probe.vpk';line=call('remote-package-sha',H+[f'cd {remote} && sha256sum --quiet -c INPUTS.sha256 && sha256sum {rel}']).decode().split();assert len(line)==2 and line[1]==rel
        package=call('download-package',H+[f'cat {remote}/{rel}'],binary=True);assert sha(package)==line[0]
        with tempfile.TemporaryDirectory(prefix='wp0102-verify-') as temp:
            q=Path(temp)/'probe.vpk';q.write_bytes(package);facts=json.loads(call('local-package-positive',[sys.executable,'-B',str(D/'verify_package.py'),str(q)]))
            assert facts['passed'] and facts['version']=='01.02' and facts['sha256']==sha(package)
            with zipfile.ZipFile(io.BytesIO(package)) as z:members={i.filename:(i,z.read(i.filename)) for i in z.infolist()}
            def variant(label,change):
                dest=Path(temp)/(label+'.vpk')
                with zipfile.ZipFile(dest,'w') as z:
                    for n,(info,b) in members.items():
                        new=change(n,b)
                        if new is not None:z.writestr(info,new)
                    if label=='extra-member':z.writestr('unexpected.txt',b'not approved')
                call('negative-'+label,[sys.executable,'-B',str(D/'verify_package.py'),str(dest)],expected=1)
            variant('missing-member',lambda n,b:None if n=='eboot2.bin' else b)
            variant('extra-member',lambda n,b:b)
            variant('wrong-foreground-version',lambda n,b:b.replace(b'01.02\0',b'01.03\0',1) if n=='sce_sys/param.sfo' else b)
            variant('wrong-background-title',lambda n,b:b.replace(b'WBLB00079\0',b'WBLB99999\0',1) if n=='sce_sys/param2.sfo' else b)
            def bad_auth(n,b):
                if n!='eboot2.bin':return b
                data=bytearray(b);info=struct.unpack_from('<Q',data,0x38)[0];struct.pack_into('<Q',data,info,0x2f00000000000001);return bytes(data)
            variant('worker-permission-escalation',bad_auth)
        assert sha(manifest(frozen()))==identity
        target=D/'build'/('wb-wake-probe-0102-'+sha(package)[:12]+'.vpk');target.parent.mkdir(exist_ok=True)
        with target.open('xb') as f:f.write(package)
        assert target.read_bytes()==package
        report.update(passed=True,package=str(target),package_facts=facts,remote=remote,host_native_cases=a.cases,semantic_package_negatives=5)
        print(json.dumps(dict(package=str(target),bytes=len(package),sha256=sha(package),members=facts['members'],evidence=str(out)),indent=2))
    except Exception as exc:report['error']=repr(exc);raise
    finally:
        report['source_after']=sha(manifest(frozen()));out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print('probe build record',out,'passed',report['passed'])
if __name__=='__main__':main()
