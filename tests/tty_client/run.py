"""Wire compatibility with the real PTY editor and TTY1 C implementation; no network/device."""
import contextlib, hashlib, json, os, queue, subprocess, sys, tempfile, threading, types
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent; R=HERE.parents[1];sys.path.insert(0,str(R/'tools'))
import wbterm as w

class Channel:
    def __init__(self,exe):
        self.p=subprocess.Popen([str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
        self.q=queue.Queue();self.sends=[]
        def drain():
            while True:
                v=os.read(self.p.stdout.fileno(),103)
                self.q.put(v)
                if not v:return
        self.thread=threading.Thread(target=drain,daemon=True);self.thread.start()
    def recv(self,n):return self.q.get(timeout=4)
    def settimeout(self,n):pass
    def recv_stderr_ready(self):return False
    def sendall(self,b):
        self.sends.append(b);self.p.stdin.write(b);self.p.stdin.flush()
    def exit_status_ready(self):return self.p.poll() is not None
    def recv_exit_status(self):return self.p.wait(timeout=4)
    def __enter__(self):return self
    def __exit__(self,*e):
        self.p.stdin.close()
        try:self.p.wait(timeout=4)
        finally:
            if self.p.poll() is None:self.p.kill()
            self.thread.join(timeout=4);self.p.stdout.close()

def refuses(fn,exc=w.Refused):
    try:fn()
    except exc:return
    raise AssertionError('expected exception '+exc.__name__)

def trust():
    calls=[];public=b'changed';expected_sha='0'*64
    class FakeChannel(contextlib.nullcontext):
        def __init__(self):super().__init__(self);self.initial=b'VITA AGENT TERMINAL 01.65 (Workbench)\r\nType help for commands.\r\nux0:/> '
        def settimeout(self,n):pass
        def recv_stderr_ready(self):return False
        def recv(self,n):
            data=self.initial;self.initial=b'';return data
        def get_pty(self,**kw):calls.append('pty')
        def invoke_shell(self):calls.append('shell')
    class Transport(contextlib.nullcontext):
        session_id=b'session'
        def __init__(self,*a):super().__init__(self)
        def start_client(self,timeout):calls.append('key-exchange')
        def get_remote_server_key(self):
            return types.SimpleNamespace(get_name=lambda:w.pin.ALGO,asbytes=lambda:public)
        def auth_publickey(self,*a):calls.append('authenticate')
        def is_authenticated(self):return True
        def is_active(self):return True
        def open_session(self,timeout):
            calls.append('channel');return FakeChannel()
    def load_owner(path):calls.append('load-owner-key');return object()
    param=types.SimpleNamespace(Transport=Transport,ECDSAKey=types.SimpleNamespace(from_private_key_file=load_owner))
    with mock.patch.dict(sys.modules,{'paramiko':param}),mock.patch.object(w.pin,'pin_path',return_value=None),mock.patch.object(w.pin,'canonical_saved',side_effect=lambda *args:(None,expected_sha)),mock.patch.object(w.socket,'create_connection',return_value=contextlib.nullcontext(object())):
        def opening():
            with w.paired_terminal():raise AssertionError('shell opened')
        refuses(opening)
        assert calls==['key-exchange']
        calls.clear();expected_sha=w.digest(public)
        with w.paired_terminal() as t:assert t.host_pin==expected_sha
        assert calls==['key-exchange','load-owner-key','authenticate','channel','pty','shell']

def main():
    trust()
    for bad in ['ux0:/a/../b','ux0:/a\\nls','ux0:/x\x00f','ux0:/a" z','ux0:/bad;bye','ux0:/a//b']:
        refuses(lambda: w.quoted_path(bad))
    for args in [['photo-export'],['reboot'],['get','ux0:/x'],['ls','-x'],['ext','rm','ux0:/foo']]:
        refuses(lambda:w.read_command(args))
    with tempfile.TemporaryDirectory() as td:
        d=Path(td);c=R/'source';exe=d/('wire.exe' if os.name=='nt' else 'wire')
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-DWB_TTY_FILE','-I'+str(c),
            str(HERE/'peer.c'),*[str(c/(x+'.c')) for x in ('wb_shell_channel','wb_tty_file','wb_shell','wb_cmd','wb_out','wb_str','wb_sha256')],'-o',str(exe)],check=True)
        f=d/'binary.bin'; data=bytes(range(256))*37+b'\x00\x1b\r\n'; f.write_bytes(data)
        remote='ux0:/VITA-POC/space file.bin'
        with Channel(exe) as ch:
            t=w.Terminal(ch);assert t.check()['channel']=='one interactive PTY'
            receipt=t.push(f,remote)
            assert receipt['sha256']==hashlib.sha256(data).hexdigest() and receipt['bytes']==len(data)
            local=d/'out.bin';assert t.pull(remote,local)['sha256']==receipt['sha256']
            assert local.read_bytes()==data
            sent=len(ch.sends);refuses(lambda:t.pull(remote,local));assert len(ch.sends)==sent
            assert len([b for b in ch.sends if b.startswith(b'D ')])==5
            assert len([b for b in ch.sends if b.startswith(b'NEXT ')])==5
            assert sum(b==b'END\n' for b in ch.sends)==2
            refuses(lambda:t.push(f,remote))
        with Channel(exe) as ch:
            t=w.Terminal(ch);t.push(f,remote)
            reply=t.reply
            def corrupt():
                v=reply()
                return v[:-64]+'0'*64 if v.startswith('TTY1 OK GET ') else v
            t.reply=corrupt;dst=d/'wrong.bin';refuses(lambda:t.pull(remote,dst))
            assert not dst.exists() and not list(d.glob('.wbterm-*.partial'))
        with Channel(exe) as ch:
            t=w.Terminal(ch);t.push(f,remote);dst=d/'race.bin'
            real=w.os.link
            def race(stage,dest):dest.write_bytes(b'owner');real(stage,dest)
            with mock.patch.object(w.os,'link',side_effect=race):
                refuses(lambda:t.pull(remote,dst),FileExistsError)
            assert dst.read_bytes()==b'owner' and not list(d.glob('.wbterm-*.partial'))
        with Channel(exe) as ch:
            t=w.Terminal(ch);f.write_bytes(b'\xff\xd8\xfffixture\xff\xd9')
            assert t.push(f,'ux0:/VITA-POC/photo.jpg',image=True)['photo_export']=='confirmed'
            assert sum(b.startswith(b'photo-export ') for b in ch.sends)==1
        with Channel(exe) as ch:
            t=w.Terminal(ch);result=t.read_and_exit(['cat','ux0:/VITA-POC/example.txt'])
            assert result['stdout']=='before\nux0:/> exit\nBye.\nafter fake prompt\n'
            assert result['shell_exit']==0 and len(ch.sends)==2
        with Channel(exe) as ch:
            t=w.Terminal(ch);t.version='01.64'
            refuses(lambda:t.push(f,remote));assert not ch.sends
        tree=w.wb_tree;fld=d/'Folder with spaces';(fld/'empty dir').mkdir(parents=True);sub=fld/'sub';sub.mkdir()
        empty=sub/'empty.txt';empty.write_bytes(b'')
        binary=sub/'nested.bin';binary.write_bytes(data)
        text=d/'extra.txt';text.write_bytes(b'extra\n')
        p=tree.plan([fld,text],tree.ROOT,True,w.quoted_path)
        with Channel(exe) as ch:
            t=w.Terminal(ch);r=tree.send(t,p,w.quoted_path)
            assert r['complete'] and r['entries_planned']==6 and r['files_planned']==3 and len(r['receipts'])==6
            assert len({x['remote'] for x in r['receipts']})==6
            assert sum(x.get('bytes',0) for x in r['receipts'])==len(data)+6
            assert t.one('tree-stat "'+tree.ROOT+'/Folder with spaces/empty dir"')=='TTY1 OK DIR'
            for local,remote_name in ((binary,'/Folder with spaces/sub/nested.bin'),(empty,'/Folder with spaces/sub/empty.txt'),(text,'/extra.txt')):
                got=d/('ret-'+local.name)
                t.pull(tree.ROOT+remote_name,got);assert got.read_bytes()==local.read_bytes()
            z=d/'new.txt';z.write_bytes(b'no partial collision')
            collision=tree.plan([z,text],tree.ROOT,False,w.quoted_path)
            before=len(ch.sends);refuses(lambda:tree.send(t,collision,w.quoted_path),tree.TreeError)
            assert all(x.startswith(b'tree-stat ') for x in ch.sends[before:])
            assert t.one('tree-stat "'+tree.ROOT+'/new.txt"')=='TTY1 OK ABSENT'
            assert t.check()['channel']=='one interactive PTY'
        with Channel(exe) as ch:
            t=w.Terminal(ch)
            with mock.patch.object(t,'push',side_effect=TimeoutError('receipt lost')):
                try:tree.send(t,p,w.quoted_path)
                except tree.PartialSend as e:
                    r=e.report;assert not r['complete'] and r['unconfirmed'].endswith('/sub/empty.txt')
                    assert len(r['receipts'])==3 and all(x['action']=='mkdir' for x in r['receipts'])
                else:raise AssertionError('missing partial batch evidence')
        refuses(lambda:tree.plan([fld],tree.ROOT,False,w.quoted_path),tree.TreeError)
        refuses(lambda:tree.plan([text,text],tree.ROOT,False,w.quoted_path),tree.TreeError)
        refuses(lambda:tree.plan([text],'ux0:/data',False,w.quoted_path),tree.TreeError)
        refuses(lambda:tree.plan([text],tree.ROOT+'/a'*12,False,w.quoted_path),tree.TreeError)
        refuses(lambda:tree.plan([fld/'..'/'extra.txt'],tree.ROOT,False,w.quoted_path),tree.TreeError)
        with mock.patch.object(tree,'MAX_ENTRIES',2):
            refuses(lambda:tree.plan([fld],tree.ROOT,True,w.quoted_path),tree.TreeError)
        with mock.patch.object(tree,'MAX_BYTES',3):
            refuses(lambda:tree.plan([text],tree.ROOT,False,w.quoted_path),tree.TreeError)
        with Channel(exe) as ch:
            t=w.Terminal(ch);text.write_bytes(b'changed after preflight')
            refuses(lambda:tree.send(t,p,w.quoted_path),tree.TreeError)
            assert all(x.startswith(b'tree-stat ') for x in ch.sends)
        # This check exercises the Windows junction/reparse bit even on POSIX CI
        # with no link privileges.
        class Reparse:
            def lstat(self):return types.SimpleNamespace(st_mode=0o100000,st_file_attributes=0x400)
        refuses(lambda:tree.unlinked(Reparse()),tree.TreeError)
    print('PASS multi-source,no-merge PTY tree send: preserve nested binary, empty file/dir, spaces; pull exact bytes; same PTY check')
    print('PASS upfront remote collision/local mutation, traversal, reparse, depth/limits policy; interrupted batch preserves item receipts')
    print('PASS PTY client: matching pin -> owner auth -> one PTY -> shell; changed key stops before owner key; command/path refusals; no <01.65 transfer fallback')
    print('PASS fragmented 5-frame binary upload/download through product C shell and TTY1 w/ memory storage, exact bytes+SHA, one-channel ver/status/ver')
    print('PASS existing remote and local file refusal, destination-race, corrupted get receipt + temp cleanup; one photo dispatch, fixture only')
    print('PASS read-only transcript drains to real EOF + exit status despite embedded fake exit/prompt; no network, system Photos or physical Vita')

if __name__=='__main__':main()
