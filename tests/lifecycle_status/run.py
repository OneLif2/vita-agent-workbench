"""Replay managed-app status with the two exact Lifecycle packages. No Vita."""
from pathlib import Path
import hashlib,subprocess,tempfile,zipfile
D=Path(__file__).resolve().parent
R=D.parents[1]
S=R/'source'
P=R.parent/'v1.79'
PACKAGES={
    'old':(P/'wake-lifecycle/build/wb-lifecycle-15c40b646963.vpk','15c40b646963cae1e6faefce52f27f6e0eaa75be3add4ff1223e99936c62f4ef'),
    'new':(P/'wake-lifecycle-startup-rc1/candidate/build/wb-lifecycle-0101-2a3a6cf25083.vpk','2a3a6cf25083a6e81e2c55eb12eea1ede88bbb24d566c0a0ee915dcb7b7264cd'),
    'plain':(R.parent/'v1.73/build/testapp.vpk','fea70dc69399200bdf00ca145044cac7725b4987d19da9d032ff2dbfd12a43e9'),
}
def inputs(d):
    src=(S/'vita_ssh_status.c').read_text(encoding='utf8')
    i=src.index('        case WB_CMD_TERM_USER_STATUS:')
    (d/'dispatch.inc').write_text(src[i:src.index('        case WB_CMD_TERM_SSH_VITA_STATUS:',i)],encoding='utf8')
    helpers=(S/'wb_ssh_vita_uninstall.inc').read_text(encoding='utf8')
    (d/'database.inc').write_text(helpers[:helpers.index('static int wbu_hash_file(')],encoding='utf8')
    for tag,(p,sha) in PACKAGES.items():
        assert hashlib.sha256(p.read_bytes()).hexdigest()==sha
        with zipfile.ZipFile(p) as z:
            for m,name in [('sce_sys/param.sfo','sfo'),('eboot.bin','boot')]:
                (d/(tag+'-'+name)).write_bytes(z.read(m))
def build(d):
    exe=d/'fixture.exe'
    cmd=['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(d),'-I'+str(S),'-I'+str(R/'tests/stub'),
         str(D/'native.c'),*(str(S/(n+'.c')) for n in ('wb_shell','wb_cmd','wb_out','wb_str','wb_sha256','wb_sfo')),'-o',str(exe)]
    subprocess.run(cmd,cwd=d,check=True)
    return exe
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:
        d=Path(t);inputs(d);subprocess.run([str(build(d))],cwd=d,check=True)
