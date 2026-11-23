"""Install the exact pi@Vita match in the current owner's Windows OpenSSH config.
No key is copied, enrolled, regenerated or printed. Back up the original in .ssh.
Optionally put the release's command-only bin directory last on the user PATH.
"""
import argparse, datetime, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
import wbctl, r1ctl
R=Path(__file__).resolve().parents[1]
MATCH='# Workbench managed: pi@192.0.2.10 only (01.60)'
def require(ok,reason):
    if not ok: raise RuntimeError(reason)
def digest(b):return hashlib.sha256(b).hexdigest()
def config(f,dest):
    cmd=['ssh','-G']+(['-F',str(f)] if f is not None else [])+[dest]
    p=subprocess.run(cmd,capture_output=True,check=True,text=True)
    return p.stdout.replace('\r\n','\n')
def values(g,k):return [s.split(' ',1)[1] for s in g.splitlines() if s.startswith(k+' ')]
def install():
    host,user,port=r1ctl.HOST,r1ctl.USER,r1ctl.PORT
    require((wbctl.HOST,wbctl.USER,int(wbctl.PORT))==(host,user,port),'unexpected endpoint')
    fp,pinhash=r1ctl.local_trust()
    pin,_=r1ctl.pin.canonical_saved(r1ctl.pin.pin_path(host,port),host,port)
    owner=Path(wbctl.KEY).resolve()
    require(owner.is_file() and not owner.is_symlink(),'owner key not available')
    for x in (str(owner),str(pin)):
        require(x.isascii() and not any(c in x for c in ['"','\n','\r','%','$']),'unsupported SSH path')
    home=Path.home()/'.ssh';cfg=home/'config';require(not cfg.is_symlink(),'refuse config symlink')
    before=cfg.read_bytes() if cfg.exists() else b'';require(not before.startswith((b'\xff\xfe',b'\xfe\xff')) and b'\0' not in before,'unsupported encoding')
    remote=f'{user}@{host}';block=(f'{MATCH}\nMatch originalhost {host} user {user}\n'
        f'    Port {port}\n    IdentityFile "{owner.as_posix()}"\n    IdentitiesOnly yes\n'
        f'    UserKnownHostsFile "{pin.as_posix()}"\n    GlobalKnownHostsFile none\n'
        '    StrictHostKeyChecking yes\n    UpdateHostKeys no\n    VerifyHostKeyDNS no\n'
        '    HostKeyAlgorithms ecdsa-sha2-nistp256\n    PreferredAuthentications publickey\n'
        '    BatchMode yes\n    ForwardAgent no\n    ConnectTimeout 8\nMatch all\n# End Workbench 01.60\n').encode('ascii')
    def verify(g):
        for k,v in [('port',str(port)),('user',user),('hostname',host),('stricthostkeychecking','true'),('identitiesonly','yes'),('hostkeyalgorithms','ecdsa-sha2-nistp256')]:
            require(values(g,k) in ([v],['yes'] if v=='true' else [v]),'ssh -G mismatch: '+k+': '+str(values(g,k)))
        require(values(g,'userknownhostsfile')==[pin.as_posix()] and owner.as_posix() in values(g,'identityfile'),'incorrect pinned files')
    ts=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');report={'pin_sha256':fp,'pin_file_sha256':pinhash};old=config(None,remote)
    original={d:config(None,d) for d in ('pi','other@'+host,'pi@192.0.2.55')}
    if MATCH.encode() not in before:
        after=before+(b'\n' if before and not before.endswith(b'\n') else b'')+b'\n'+block
        with tempfile.NamedTemporaryFile(dir=home,delete=False) as t:tmp=Path(t.name);t.write(after)
        try:
            verify(config(tmp,remote))
            for other,v in original.items():require(config(tmp,other)==v,'unrelated host config changed: '+other)
            require((cfg.read_bytes() if cfg.exists() else b'')==before,'config changed; stopping')
            bk=home/('config.before-workbench-'+ts+'.bak')
            if cfg.exists():
                with bk.open('xb') as f:f.write(before)
            os.replace(tmp,cfg);report['original_backup']=str(bk) if before else None
        finally:tmp.unlink(missing_ok=True)
    verify(config(None,remote))
    require(all(config(None,k)==v for k,v in original.items()),'unexpected unrelated host change')
    report.update(config=str(cfg),old_sha=digest(before),new_sha=digest(cfg.read_bytes()),old_port=values(old,'port'),new_port=values(config(None,remote),'port'),jetson_unchanged=True)
    f=R/'evidence'/('host-config-'+ts+'.json');f.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print('PASS exact owner@address config; port',port,'original pin; unrelated hosts unchanged;',f)
def add_bin():
    import winreg,ctypes
    b=(R/'bin').resolve();require((b/'wb.cmd').is_file() and [x.name for x in b.iterdir()]==['wb.cmd'],'unexpected tools to expose via PATH')
    dupe=shutil.which('wb');require(not dupe or Path(dupe).resolve()==b/'wb.cmd','different command already named wb')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,'Environment',0,winreg.KEY_QUERY_VALUE|winreg.KEY_SET_VALUE) as key:
        try:raw,typ=winreg.QueryValueEx(key,'Path')
        except FileNotFoundError:raw,typ='',winreg.REG_EXPAND_SZ
        require(typ in (winreg.REG_SZ,winreg.REG_EXPAND_SZ),'unexpected PATH type')
        if str(b).lower() not in [s.strip('"').lower() for s in raw.split(';')]:
            new=raw+(';' if raw and not raw.endswith(';') else '')+str(b)
            winreg.SetValueEx(key,'Path',0,typ,new)
            require(winreg.QueryValueEx(key,'Path')==(new,typ),'PATH write failed')
    ctypes.windll.user32.SendMessageTimeoutW(0xffff,0x1a,0,'Environment',2,1000,None)
    print('wb put et al: new CMD user PATH entry',b)
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--install',action='store_true',required=True);ap.add_argument('--add-wb-command',action='store_true')
    args=ap.parse_args();install()
    if args.add_wb_command:add_bin()
