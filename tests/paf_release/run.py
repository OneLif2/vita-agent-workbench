"""Exercise two real release helpers with identical, bounded host stubs; never opens a socket.
--observe --root DIR: print the before/authorized-on-present/delete/after trace for DIR.
DIR may be an extracted release; only source/ and updater/main.c are read from it.
"""
import argparse,hashlib,json,subprocess,tempfile,zipfile
from pathlib import Path
P=Path(__file__).resolve().parent; R=P.parents[1]
def need(b,s):
    if not b: raise AssertionError(s)
def cut(s,a,b):
    begin=s.index(a);return s[begin:s.index(b,begin)]
def trace(root,vpk,scenarios=(0,),n=1):
    s=root/'source'
    native=(s/'wb_vita_install.c').read_text()
    updater=(root/'updater/main.c').read_text()
    if '#include "wb_paf_release.h"' in native:
        need('#include "../source/wb_paf_release.h"' in updater,'standalone updater diverges')
        impl=(s/'wb_paf_release.h').read_text()
    else:
        impl=cut(native,'static int unload_paf(void) {','\n}\n')+'\n}\n'
        need(impl in updater,'inconsistent older core/updater implementations')
    with tempfile.TemporaryDirectory() as td:
        t=Path(td)
        data=vpk.read_bytes()
        need(hashlib.sha256(data).hexdigest()=='e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce','untrusted fixture VPK')
        with zipfile.ZipFile(vpk) as z:
            for member,name in [('eboot.bin','boot'),('sce_sys/param.sfo','sfo')]:
                (t/name).write_bytes(z.read(member))
        (t/'under_test.inc').write_text(impl)
        (t/'adapter.inc').write_text(cut((s/'vita_ssh_status.c').read_text(),
                   '        case WB_CMD_TERM_SSH_VITA_STATUS:', '        case WB_CMD_TERM_FONT:'))
        f=(R/'tests/ssh_vita_uninstall/fixture.c').read_text()
        f=f[:f.index('int main(int argc,char**argv)')]
        prior='static int unload_paf(void){assert(loaded&&!mod_loaded);loaded=0;return fault==PAF_ERR?-121:0;}'
        need(f.count(prior)==1,'unexpected platform stub boundary')
        need(f.count('cal==4?9:')==1,'unexpected emulated target logic')
        f=f.replace(prior,(P/'syscall.c.in').read_text()).replace('cal==4?9:','cal==4?3:')
        (t/'mixed.c').write_text(f+(P/'main.c.in').read_text())
        exe=t/'fixture.exe'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                '-I'+str(s),'-I'+str(R/'tests/stub'),'-I'+str(t),str(t/'mixed.c'),
                *[str(s/(u+'.c')) for u in ('wb_cmd','wb_out','wb_str','wb_shell','wb_sha256','wb_sfo')],
                '-o',str(exe)],check=True)
        return {(i,k):subprocess.check_output([str(exe),str(k)],cwd=t,text=True)
                for i in range(n) for k in scenarios}
def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--observe',action='store_true')
    a.add_argument('--root',type=Path);a.add_argument('--vpk',type=Path,default=R.parent/'external/ssh-vita/v1.4.2/upstream/ssh-vita.vpk');o=a.parse_args()
    if o.observe:
        need(o.root is not None,'--root required');print(trace(o.root.resolve(),o.vpk)[0,0],end='');return
    need(o.root is None,'--root only with --observe')
    oldfile=R.parent/'iterations/remove-0172/result-20261122T090130757872Z.json'
    need(hashlib.sha256(oldfile.read_bytes()).hexdigest()=='4911fb4653e12b252f326bce7e71556a2f2ac72cb512fcd4097d776c58bc46ce','evidence changed')
    j=json.loads(oldfile.read_bytes());obs=[e['stdout'][0] for e in j['events'] if e['command']=='app status VSSH00001']
    need(len(obs)==1 and obs[0].endswith('rc=80022005 value=00000003 disk=00000001 issued=0'),'hardware tuple changed')
    old=trace(R.parent/'v1.72',o.vpk,n=3)
    for output in old.values():
        need(output.splitlines()==['before: '+obs[0],'fixture native delete calls=0 disk=1 registry=1','fixture releases=1 short_options=1'],output)
    new=trace(R,o.vpk,range(6),3)
    for (_,mode),output in new.items():
        if mode in (0,4):
            need('before: app title=VSSH00001 state=installed app_ver=01.42' in output and
                 'after: app title=VSSH00001 state=absent' in output and
                 'fixture native delete calls=1 disk=0 registry=0' in output, output)
            if not mode: need('delete: OK app-uninstall title=VSSH00001 state=absent' in output,output)
            else: need('delete: ERR app-uninstall-gate phase=paf-exit rc=80022005' in output and 'issued=1' in output,output)
        else:
            need('fixture native delete calls=0 disk=1 registry=1' in output and 'issued=0' in output,output)
            msg={1:'paf-exit rc=80022005',2:'paf-exit rc=FFFFFF87',3:'paf-exit rc=80022005',5:'eboot-identity'}[mode]
            need(msg in output,output)
        need('short_options=0' in output,output)
    print('PASS paf_release: 3 repeats each of previous 4-byte failure and 6 new scenarios (21 fixture runs).')
    print(old[0,0],end='');print(new[0,0],end='')
    print('Negative: unchanged syscall error, module-result error, syscall priority, post-delete cleanup failure not blanketed as success, and identity mismatch; no retry. Host simulation only.')
if __name__=='__main__':main()
