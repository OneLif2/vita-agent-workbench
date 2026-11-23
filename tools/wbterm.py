"""5090 adapter: one pinned interactive SSH terminal, no alternate device channel."""
from __future__ import annotations
import argparse, contextlib, hashlib, hmac, json, os, re, socket, stat, sys, tempfile, time
from pathlib import Path
import pinned_check as pin
import wb_tree
from check_in_place import VR, ST

HOST, PORT, USER = '192.0.2.10', 2222, 'pi'
ROOT_PROMPT = b'ux0:/> '
LIMIT, CHUNK, PHOTO_MAX = 192 * 1024 * 1024, 2048, 8 * 1024 * 1024

class Refused(ValueError):
    pass

class TrustRefused(Refused):
    pass

class Inconclusive(RuntimeError):
    pass

def require(ok, message):
    if not ok:
        raise Refused(message)

def digest(b):
    return hashlib.sha256(b).hexdigest()

def quoted_path(path):
    """Only canonical ASCII ux0:/ paths. Never interpret client-supplied shell syntax."""
    require(path.startswith('ux0:/') and len(path) < 128, 'expected absolute ux0:/ path under 128 ASCII bytes')
    for part in path[5:].split('/'):
        require(re.fullmatch(r'[a-zA-Z0-9_(). +@-]{1,100}', part) and part.strip() == part
                and not part.endswith('.') and part not in ('.', '..'), 'unsupported path segment')
    return '"' + path + '"'

@contextlib.contextmanager
def paired_terminal():
    """Verify saved exact server key BEFORE offering the owner key; open only one PTY/shell."""
    _, expected = pin.canonical_saved(pin.pin_path(HOST, PORT), HOST, PORT)
    import paramiko
    with socket.create_connection((HOST, PORT), timeout=7) as sock:
        with paramiko.Transport(sock) as transport:
            transport.banner_timeout = transport.auth_timeout = 8
            transport.start_client(timeout=8)
            key = transport.get_remote_server_key()
            if key.get_name() != pin.ALGO or not hmac.compare_digest(digest(key.asbytes()), expected):
                raise TrustRefused('Vita host key differs: stopped before owner-key authentication')
            owner = Path(os.environ.get('WB_KEY', str(Path.home()/'.ssh/id_ecdsa_wb')))
            transport.auth_publickey(USER, paramiko.ECDSAKey.from_private_key_file(str(owner)))
            require(transport.is_authenticated() and transport.is_active(), 'owner key not accepted')
            with transport.open_session(timeout=8) as ch:
                ch.settimeout(12)
                ch.get_pty(term='vt100', width=80, height=24)
                ch.invoke_shell()
                yield Terminal(ch, expected, digest(bytes(transport.session_id)))

class Terminal:
    def __init__(self, channel, host_pin='fixture', transport_id='fixture'):
        self.ch, self.host_pin, self.transport_id = channel, host_pin, transport_id
        self.buf = bytearray()
        self.deadline = time.monotonic() + 1800
        m = re.fullmatch(rb'VITA AGENT TERMINAL (\d\d\.\d\d) \(Workbench\)', self.line())
        require(m and self.line() == b'Type help for commands.', 'unexpected Workbench shell')
        self.version = m[1].decode('ascii')
        self.exact(ROOT_PROMPT)

    def _more(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError('terminal total time limit')
        if self.ch.recv_stderr_ready():
            raise Inconclusive('unexpected terminal stderr')
        b = self.ch.recv(4096)
        if not b:
            raise Inconclusive('terminal closed before expected receipt')
        self.buf.extend(b)
        require(len(self.buf) < 12352, 'oversized terminal frame')

    def line(self):
        while b'\n' not in self.buf:
            require(len(self.buf) <= 5120, 'oversized line')
            self._more()
        i = self.buf.index(10) + 1
        val = bytes(self.buf[:i])
        del self.buf[:i]
        require(len(val) <= 5120 and val.endswith(b'\r\n'), 'invalid terminal framing')
        return val[:-2]

    def exact(self, token):
        while len(self.buf) < len(token):
            self._more()
        require(self.buf.startswith(token), 'unexpected terminal prompt or echo')
        del self.buf[:len(token)]

    def send(self, text):
        b = text.encode('ascii')
        require(len(b) <= (2*CHUNK+32) and all(32 <= c < 127 for c in b), 'invalid frame')
        self.ch.sendall(b+b'\n')

    def command(self, text):
        require(len(text) < 512, 'command too long')
        self.send(text)
        self.exact(text.encode('ascii')+b'\r\n')

    def reply(self):
        s = self.line().decode('ascii')
        if s.startswith(('ERR ', 'TTY1 ERR ')):
            # Never print unbounded/malformed remote strings or terminal control bytes.
            raise Refused('Vita refused: ' + ascii(s[:180]))
        return s

    def one(self, text):
        self.command(text)
        result = self.reply()
        self.exact(ROOT_PROMPT)
        return result

    def check(self):
        a, b, c = VR.fullmatch(self.one('ver')), ST.fullmatch(self.one('status')), VR.fullmatch(self.one('ver'))
        require(a and b and c and a.groups()[:6] == c.groups()[:6] and self.version == a[1] == b[6]
                and b[1] == a[5] and b[3] == 'connected' and b[5] == a[6]
                and int(a[7]) <= int(b[2]) <= int(c[7]), 'same-run ver/status/ver check failed')
        return dict(version=a[1], build=a[2], run=a[5], channel='one interactive PTY',
                    host_sha256=self.host_pin, transport_sha256=self.transport_id)

    def require_transfer(self):
        require(self.version >= '01.65', 'this shell predates PTY file transfers; no fallback')

    def read_and_exit(self, args):
        """A read-only *terminal transcript*, not a status-code/RPC protocol for text files.
        A filename or cat payload can look exactly like a shell prompt. Drain to actual
        ordered SSH EOF/exit-status, then strip the expected final prompt/exit receipt.
        """
        return self._transcript_and_exit(read_command(args))

    def _transcript_and_exit(self,cmd,timeout=20):
        # Internal: callers must use one of the fixed command formatters.
        require(0<timeout<=600,'unsupported terminal command timeout')
        end=time.monotonic()+timeout
        self.ch.settimeout(max(.05,min(timeout,600)))
        self.command(cmd)
        self.send('exit')
        remaining=bytearray(self.buf);self.buf.clear()
        while True:
            require(time.monotonic()<end and not self.ch.recv_stderr_ready(),'unexpected stderr / timed out')
            self.ch.settimeout(max(.05,end-time.monotonic()))
            chunk=self.ch.recv(4096)
            if not chunk:break
            remaining.extend(chunk)
            require(len(remaining)<=65536,'oversized text response')
        while not self.ch.exit_status_ready() and time.monotonic()<end:time.sleep(.008)
        require(self.ch.exit_status_ready() and self.ch.recv_exit_status()==0,'missing graceful exit')
        tail=ROOT_PROMPT+b'exit\r\nBye.\r\n'
        require(remaining.endswith(tail),'missing final exit receipt')
        out=bytes(remaining[:-len(tail)]).decode('ascii').replace('\r\n','\n')
        require(all(c=='\n' or 32<=ord(c)<127 for c in out),'invalid control characters')
        return dict(command=cmd,stdout=out,shell_exit=0,host_sha256=self.host_pin,
                    transport_sha256=self.transport_id)

    def push(self, local, remote, image=False, *, snapshot=None):
        self.require_transfer()
        dest = quoted_path(remote)
        with wb_tree.checked_open(local,snapshot) as f:
            st = os.fstat(f.fileno())
            require(stat.S_ISREG(st.st_mode) and (st.st_size>0 or (not image and self.version>='01.66'))
                    and st.st_size <= (PHOTO_MAX if image else LIMIT),
                    'local file exceeds limit or peer does not support an empty upload')
            size = st.st_size
            h = hashlib.sha256()
            seen = 0
            while (block := f.read(65536)):
                seen += len(block)
                require(seen <= size, 'source grew before upload')
                h.update(block)
            require(seen == size, 'source changed before transfer')
            sha = h.hexdigest()
            f.seek(0)
            if image:
                suffix = Path(remote).suffix.lower()
                raw = f.read(PHOTO_MAX+1)
                require(valid_image(raw, suffix), 'expected complete JPEG/PNG matching device suffix')
                f.seek(0)
            self.command(f'put {dest} {size} sha256={sha}')
            require(self.reply() == f'TTY1 READY PUT {size} {CHUNK}', 'unexpected put acknowledgement')
            pos = 0
            while pos < size:
                data = f.read(min(CHUNK, size-pos))
                require(data, 'source truncated mid-transfer')
                self.send(f'D {pos} {data.hex()}')
                pos += len(data)
                require(self.reply() == f'TTY1 ACK {pos}', 'upload offset mismatch')
            require(not f.read(1) and wb_tree.signature(os.fstat(f.fileno()))==wb_tree.signature(st),
                    'source changed during transfer')
            # Once END has been sent, a lost receipt is NOT evidence that the upload failed.
            self.send('END')
            try:
                line=self.reply()
                if line != f'TTY1 OK PUT {size} {sha}':
                    raise Inconclusive('put receipt did not match the sent content')
                self.exact(ROOT_PROMPT)
            except Refused:
                raise
            except Exception as exc:
                raise Inconclusive('upload completion unknown: inspect destination, do not auto-retry') from exc
        result = dict(action='put', remote=remote, bytes=size, sha256=sha)
        if image:
            try:
                result_line = self.one(f'photo-export {dest} {sha}')
                require(result_line == f'OK photo-export bytes={size} sha256={sha}', 'unknown Photos receipt')
            except Refused as exc:
                raise Inconclusive(f'image staged; Photos not confirmed ({exc}); do not auto-retry') from exc
            except Exception as exc:
                raise Inconclusive('image staged; Photos receipt lost; do not auto-retry') from exc
            result['photo_export'] = 'confirmed'
        return result

    def pull(self, remote, local, max_bytes=LIMIT):
        self.require_transfer()
        src = quoted_path(remote)
        dest = Path(local)
        require(not dest.exists() and not dest.is_symlink(), 'local destination already exists')
        stage = None
        try:
            # Stage in the destination directory; publish exclusively only AFTER Vita's receipt.
            with tempfile.NamedTemporaryFile(dir=dest.parent, prefix='.wbterm-', suffix='.partial',delete=False) as out:
                stage = Path(out.name)
                self.command('get '+src)
                m = re.fullmatch(r'TTY1 READY GET (0|[1-9]\d{0,8}) 2048',self.reply())
                require(m and int(m[1]) <= min(max_bytes,LIMIT),'unexpected get size')
                size = int(m[1]); pos = 0; h = hashlib.sha256()
                while pos < size:
                    self.send('NEXT '+str(pos))
                    r = re.fullmatch(r'TTY1 DATA (0|[1-9]\d{0,8}) ([0-9a-f]{2,4096})',self.reply())
                    require(r and int(r[1]) == pos and len(r[2])%2 == 0,'invalid download frame')
                    block = bytes.fromhex(r[2])
                    require(0 < len(block) <= size-pos,'download exceeds announced size')
                    out.write(block); h.update(block); pos += len(block)
                self.send('END'); sha = h.hexdigest()
                require(self.reply() == f'TTY1 OK GET {size} {sha}', 'download SHA-256/size mismatch')
                self.exact(ROOT_PROMPT)
                out.flush();os.fsync(out.fileno())
            os.link(stage,dest)  # Fails closed on existing destination or filesystems without hardlinks.
            return dict(action='get',remote=remote,local=str(dest.absolute()),bytes=size,sha256=sha)
        finally:
            if stage is not None:
                stage.unlink(missing_ok=True)

def valid_image(b, suffix):
    if suffix in ('.jpg','.jpeg'):
        return len(b)>=5 and b.startswith(b'\xff\xd8\xff') and b.endswith(b'\xff\xd9')
    import struct
    return (suffix=='.png' and len(b)>=45 and b.startswith(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')
            and all(struct.unpack('>II',b[16:24])) and b.endswith(bytes.fromhex('0000000049454e44ae426082')))

def read_command(args):
    require(args,'missing read-only command')
    op,*tail=args
    if op in ('help','pwd','ver','status','pending','timeline','df','r1-status') and not tail:return op
    if op=='ls':
        flag=tail[:1]==['-l']
        if flag:tail=tail[1:]
        require(len(tail)<=1,'usage: ls [-l] [absolute path]')
        return 'ls'+(' -l' if flag else '')+((' '+('"/"' if tail[0] in ('/','ux0:/') else quoted_path(tail[0]))) if tail else '')
    if op in ('cat','plan','inspect') and len(tail)==1:return op+' '+quoted_path(tail[0])
    if op=='ext' and tail in (['sys'],['hello'],['features']):return 'ext '+tail[0]
    if op=='ext' and len(tail)==2 and tail[0]=='stat':return 'ext stat '+quoted_path(tail[1])
    raise Refused('not on the read-only list; use the interactive Workbench terminal')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    commands=p.add_subparsers(dest='action',required=True)
    commands.add_parser('check',help='ver -> status -> ver in one shell')
    ro=commands.add_parser('read',help='one read-only command; capture output until graceful shell exit')
    ro.add_argument('args',nargs=argparse.REMAINDER)
    push=commands.add_parser('push',help='send one local file via the terminal');push.add_argument('local');push.add_argument('remote');push.add_argument('--image',action='store_true')
    send=commands.add_parser('send',help='send files and new directory trees in one paired shell; no overwrite or merge')
    send.add_argument('-r','--recursive',action='store_true',help='include directories, their children and empty entries')
    send.add_argument('sources',nargs='+',metavar='SOURCE')
    send.add_argument('--to',required=True,help='existing parent under ux0:/VITA-POC; each source keeps its name')
    pull=commands.add_parser('pull',help='read one file via the terminal');pull.add_argument('remote');pull.add_argument('local')
    a=p.parse_args()
    try:
        if a.action=='read':read_command(a.args)
        if a.action=='send':batch=wb_tree.plan(a.sources,a.to,a.recursive,quoted_path)
        with paired_terminal() as t:
            if a.action=='check': result=t.check()
            elif a.action=='read': result=t.read_and_exit(a.args)
            elif a.action=='push': result=t.push(a.local,a.remote,a.image)
            elif a.action=='send': result=wb_tree.send(t,batch,quoted_path)
            else: result=t.pull(a.remote,a.local)
        print(json.dumps(result));return 0
    except wb_tree.PartialSend as exc:
        print(json.dumps(exc.report));return 2
    except (Exception, KeyboardInterrupt) as exc:
        # Closing the sole SSH channel cancels an unfinished transfer. No automatic retries.
        print(f'{type(exc).__name__}: {str(exc)[:240]}',file=sys.stderr);return 2

if __name__=='__main__':
    sys.exit(main())
