"""5090 adapter: one pinned interactive SSH terminal, no alternate device channel."""
from __future__ import annotations
import argparse, contextlib, hashlib, hmac, json, math, os, re, socket, stat, sys, tempfile, time
from collections import deque
from pathlib import Path
import pinned_check as pin
import wb_tree
from check_in_place import VR, ST

HOST, PORT, USER = '192.0.2.10', 2222, 'pi'
ROOT_PROMPT = b'ux0:/> '
ROOT_PROMPTS = (
    ROOT_PROMPT,
    b'pi@vita:/ux0$ ',
    b'\x1b[1;32mpi@vita\x1b[0m:\x1b[1;34m/ux0\x1b[0m$ ',
)
# The regular-file transport follows Vita's uint32-sized file contract.
LIMIT, CHUNK, PHOTO_MAX = (1 << 32) - 1, 2048, 8 * 1024 * 1024
DEFAULT_PUT_WINDOW, MAX_PUT_WINDOW = 8, 16
BATCH_FRAMES = 8  # protocol constant, not the host's adjustable legacy window
PUT_IDLE, PUT_MAX_SECONDS = 90, 48*3600

class Refused(ValueError):
    pass

class DeviceRefused(Refused):
    """An explicit ERR line from the authenticated terminal, not a parsing error."""

class TrustRefused(Refused):
    pass

class Inconclusive(RuntimeError):
    pass

def require(ok, message):
    if not ok:
        raise Refused(message)

def digest(b):
    return hashlib.sha256(b).hexdigest()

def put_timeout_arg(s):
    n=int(s)
    if not 1<=n<=PUT_MAX_SECONDS:raise argparse.ArgumentTypeError('expected 1..172800 seconds')
    return n

class _PutBudget:
    """DATA total + exact-ACK idle deadline, then a separate bounded commit window.
    Only used on an already-authenticated PTY. Partial lines and sent bytes do not
    refresh the idle deadline. A caller-supplied absolute deadline still wins.
    """
    def __init__(self,t,size,seconds):
        self.t=t; self.size=size; self.start=time.monotonic()
        prior=getattr(t,'deadline',None)
        self.normal=prior is not None and prior==getattr(t,'_shell_deadline',None)
        self.outer=float('inf') if self.normal or prior is None else prior
        self.data_end=self.start+(seconds if seconds is not None else
            min(PUT_MAX_SECONDS,max(1800,300+(size+32767)//32768)))
        self.end=min(self.outer,self.data_end,self.start+PUT_IDLE)
        self.channel=getattr(t,'ch',None)
        self.manage_socket=callable(getattr(self.channel,'gettimeout',None))
        self.prior_timeout=self.channel.gettimeout() if self.manage_socket else None
        if self.normal and prior<=self.start:raise TimeoutError('shell expired before PUT')
    def remaining(self):
        left=self.end-time.monotonic()
        if left<=0:raise TimeoutError('PUT phase deadline exceeded')
        return left
    def arm(self):
        left=self.remaining()
        if self.manage_socket:self.channel.settimeout(left)
    def progress(self):
        self.remaining()  # do not revive an already expired ACK
        self.end=min(self.outer,self.data_end,time.monotonic()+PUT_IDLE)
    def commit(self):
        self.remaining()  # no END after expired data phase
        seconds=min(3600,max(120,60+(self.size+262143)//262144))
        self.end=min(self.outer,time.monotonic()+seconds)
    def __enter__(self):
        if getattr(self.t,'_put_budget',None) is not None:raise Refused('PUT already active')
        self.t._put_budget=self
        return self
    def __exit__(self,*args):
        del self.t._put_budget
        # Pause the ordinary 30-minute shell allowance during PUT. Explicit
        # absolute deadlines are not rewritten. Directory probes after a long
        # per-file transfer thus still get the original remaining shell time.
        if self.normal:
            self.t.deadline+=time.monotonic()-self.start
            self.t._shell_deadline=self.t.deadline
        if self.manage_socket:self.channel.settimeout(self.prior_timeout)

BAR_WIDTH = 28

def format_qty(n):
    """1024-based size. Exact bytes stay integer; larger units keep one decimal."""
    n = int(n)
    value = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if unit == 'B':
            if value < 1024:
                return f'{n} B'
        elif unit == 'TB' or value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024.0
    return f'{n} B'

def format_rate(bps):
    value = float(bps)
    for unit in ('B/s', 'KB/s', 'MB/s', 'GB/s'):
        if unit == 'B/s':
            if value < 1024:
                return f'{value:.0f} B/s'
        elif unit == 'GB/s' or value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024.0
    return f'{bps:.0f} B/s'

def format_eta(seconds):
    if seconds is None or seconds < 0 or not math.isfinite(seconds):
        return '--:--'
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f'{hours:02d}:{minutes:02d}:{secs:02d}'
    return f'{minutes:02d}:{secs:02d}'

def format_meter(label, done, total, rate, eta):
    done = int(done)
    if total is None:
        pct, filled, span = ' --%', 0, format_qty(done)
    else:
        total = int(total)
        if total <= 0 or done >= total:
            pct_n, filled = 100, BAR_WIDTH
        else:
            pct_n = (done * 100) // total
            filled = (done * BAR_WIDTH) // total
        pct = f'{pct_n:3d}%'
        span = f'{format_qty(done)}/{format_qty(total)}'
    bar = '#' * filled + '-' * (BAR_WIDTH - filled)
    return f'{label} [{bar}] {pct} {span} {rate} ETA {eta}'

class TransferMeter:
    """stderr progress for one transfer. stdout receipts stay untouched.

    A terminal redraws one line at about 10 Hz. Any other stream, including a
    captured test log, gets every sample on its own line so nothing is dropped.
    """
    def __init__(self, stream=None, clock=None, retain_all=False):
        self.stream = sys.stderr if stream is None else stream
        self.clock = clock or time.monotonic
        # App transcripts keep every sample in a log. Byte transfers stay at 10 Hz
        # so a piped upload does not print one line per 2048-byte chunk.
        self.retain_all = retain_all
        self.label = None
        self.t0 = None
        self.b0 = 0
        self.last = None
        self.pending = False
        self.last_draw = None
        self.drawn_label = None
        self.carriage = False

    def _tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        try:
            return bool(isatty and isatty())
        except Exception:
            return False

    def _sample(self, label, done, total, now):
        if self.t0 is None or label != self.label:
            self.t0, self.b0, self.label = now, done, label
        elapsed = now - self.t0
        moved = done - self.b0
        if elapsed > 0 and moved > 0:
            bps = moved / elapsed
            rate = format_rate(bps)
            if total is not None and done < total:
                eta = format_eta((total - done) / bps)
            elif total is not None and done >= total:
                eta = '00:00'
            else:
                eta = '--:--'
        else:
            rate = '--'
            eta = '00:00' if total is not None and total >= 0 and done >= total else '--:--'
        return format_meter(label, done, total, rate, eta)

    def update(self, label, done, total=None):
        done = int(done)
        total = None if total is None else int(total)
        now = self.clock()
        self.last = (label, done, total, now)
        self.pending = True
        if (self.drawn_label == label and self.last_draw is not None and now - self.last_draw < 0.1
                and (self._tty() or not self.retain_all)):
            return
        self._emit(self._sample(label, done, total, now), now, label)
        self.pending = False

    def _emit(self, text, now, label):
        if self._tty() and self.carriage and self.drawn_label not in (None, label):
            self.stream.write('\n')
            self.carriage = False
        if self._tty():
            self.stream.write('\r' + text + '   ')
            self.carriage = True
        else:
            self.stream.write(text + '\n')
        self.stream.flush()
        self.last_draw = now
        self.drawn_label = label

    def finish(self):
        if self.last and (self.pending or self._tty()):
            label, done, total, now = self.last
            self._emit(self._sample(label, done, total, now), now, label)
            self.pending = False
        if self.carriage:
            self.stream.write('\n')
            self.stream.flush()
            self.carriage = False
        self.last = None

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
    root_prompt = ROOT_PROMPT

    def __init__(self, channel, host_pin='fixture', transport_id='fixture'):
        self.ch, self.host_pin, self.transport_id = channel, host_pin, transport_id
        self.buf = bytearray()
        self.deadline = self._shell_deadline = time.monotonic() + 1800
        m = re.fullmatch(rb'VITA AGENT TERMINAL (\d\d\.\d\d) \(Workbench\)', self.line())
        require(m and self.line() == b'Type help for commands.', 'unexpected Workbench shell')
        self.version = m[1].decode('ascii')
        self.root_prompt = self._read_root_prompt()
        self.install_total = None

    def _read_root_prompt(self):
        while True:
            for tok in ROOT_PROMPTS:
                if self.buf.startswith(tok):
                    del self.buf[:len(tok)]
                    return tok
            if any(tok.startswith(bytes(self.buf)) for tok in ROOT_PROMPTS):
                self._more()
                continue
            require(False, 'unexpected terminal prompt or echo')

    def _more(self):
        budget=getattr(self,'_put_budget',None)
        if budget:budget.arm()
        elif time.monotonic() >= self.deadline:
            raise TimeoutError('terminal total time limit')
        if self.ch.recv_stderr_ready():
            raise Inconclusive('unexpected terminal stderr')
        b = self.ch.recv(4096)
        if budget:budget.remaining()
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
        self._wire_write(b+b'\n')

    def _wire_write(self, wire):
        """A validated line, or a bounded group of locally generated DATA lines."""
        budget=getattr(self,'_put_budget',None)
        if budget:budget.arm()
        if budget and callable(getattr(self.ch,'send',None)):
            # Paramiko sendall loops on short sends using the same timeout each
            # time. Clamp each individual send to the remaining absolute budget.
            while wire:
                budget.arm();n=self.ch.send(wire)
                if not 0<n<=len(wire):raise Inconclusive('terminal send closed')
                wire=wire[n:]
        else:self.ch.sendall(wire)
        if budget:budget.remaining()

    def command(self, text):
        require(len(text) < 512, 'command too long')
        self.send(text)
        self.exact(text.encode('ascii')+b'\r\n')

    def reply(self):
        s = self.line().decode('ascii')
        if s.startswith(('ERR ', 'TTY1 ERR ')):
            # Never print unbounded/malformed remote strings or terminal control bytes.
            raise DeviceRefused('Vita refused: ' + ascii(s[:180]))
        return s

    def one(self, text):
        self.command(text)
        result = self.reply()
        self.exact(getattr(self, 'root_prompt', ROOT_PROMPT))
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
        if cmd.startswith('app-install '):
            return self._app_transcript_and_exit(cmd,timeout)
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
        tail=getattr(self,'root_prompt',ROOT_PROMPT)+b'exit\r\nBye.\r\n'
        require(remaining.endswith(tail),'missing final exit receipt')
        out=bytes(remaining[:-len(tail)]).decode('ascii').replace('\r\n','\n')
        require(all(c=='\n' or 32<=ord(c)<127 for c in out),'invalid control characters')
        return dict(command=cmd,stdout=out,shell_exit=0,host_sha256=self.host_pin,
                    transport_sha256=self.transport_id)

    def _app_transcript_and_exit(self,cmd,timeout):
        """Stream app-only progress without retaining an unbounded transcript."""
        require(math.isfinite(timeout) and timeout>0,'invalid app command timeout')
        end=time.monotonic()+timeout
        self.deadline=end
        self.ch.settimeout(max(.05,timeout))
        self.command(cmd); self.send('exit')
        pending=bytearray(self.buf); self.buf.clear()
        output=bytearray()
        meter=TransferMeter(retain_all=True)
        try:
            return self._app_consume(cmd,end,pending,output,meter)
        finally:
            meter.finish()

    def _app_consume(self,cmd,end,pending,output,meter):
        count=0; last=None; phase_index=-1; phase_bytes=0; phase_total=None
        def consume(line):
            nonlocal count,last,phase_index,phase_bytes,phase_total
            require(all(32<=c<127 for c in line),'invalid app transcript control characters')
            if line.startswith(b'app-progress '):
                match=re.fullmatch(
                    rb'app-progress phase=(copy|validate|extract) bytes=(0|[1-9]\d{0,19})(?: total=(0|[1-9]\d{0,19}))?',
                    line)
                require(match and int(match[2])<=(1<<64)-1,'invalid app progress')
                phase=match[1].decode('ascii'); value=int(match[2]); index=('copy','validate','extract').index(phase)
                total=int(match[3]) if match[3] is not None else None
                if total is not None:
                    require(total<=(1<<64)-1,'invalid app progress')
                    require(value<=total,'app progress exceeds total')
                require(index>=phase_index and (index!=phase_index or value>=phase_bytes),
                        'regressing app progress')
                if index!=phase_index:
                    phase_total=None
                if total is None:
                    require(phase_total is None,'app progress total disappeared')
                else:
                    require(phase_total is None or total==phase_total,'app progress total changed')
                    phase_total=total
                phase_index,phase_bytes=index,value
                count+=1;last=dict(phase=phase,bytes=value)
                if total is not None:
                    last['total']=total
                # Copy percent can use the approved archive size when an older
                # core omits total=. Validate and extract stay byte counts until
                # the device reports their own total.
                known=total
                if phase=='copy' and known is None and type(self.install_total) is int and self.install_total>0:
                    known=self.install_total
                meter.update(phase,value,known)
            else:
                output.extend(line+b'\r\n')
                require(len(output)<=65536,'oversized app response')
        while True:
            while b'\r\n' in pending:
                split=pending.index(b'\r\n')
                consume(bytes(pending[:split])); del pending[:split+2]
            require(len(pending)<=5120,'oversized app response line')
            require(time.monotonic()<end and not self.ch.recv_stderr_ready(),'unexpected stderr / timed out')
            self.ch.settimeout(max(.05,end-time.monotonic()))
            chunk=self.ch.recv(4096)
            if not chunk:break
            pending.extend(chunk)
        require(not pending,'incomplete app response line')
        while not self.ch.exit_status_ready() and time.monotonic()<end:time.sleep(.008)
        require(self.ch.exit_status_ready() and self.ch.recv_exit_status()==0,'missing graceful exit')
        tail=getattr(self,'root_prompt',ROOT_PROMPT)+b'exit\r\nBye.\r\n'
        require(output.endswith(tail),'missing final exit receipt')
        out=bytes(output[:-len(tail)]).decode('ascii').replace('\r\n','\n')
        self.last_app_progress=dict(count=count,last=last)
        return dict(command=cmd,stdout=out,shell_exit=0,progress=self.last_app_progress,
                    host_sha256=self.host_pin,transport_sha256=self.transport_id)

    def push(self, local, remote, image=False, *, snapshot=None, window=None, timeout=None):
        # Window = unacknowledged DATA frames, not a buffer of unverified files.
        # The CLI can set a default on its *one* PTY for all files in a tree.
        # Keep old peers in stop-and-wait unless they explicitly opt in (02.11+).
        if window is None:
            window = getattr(self, 'put_window', None)
        auto_batch = window is None and self.version >= '02.14'
        if window is None:
            window = DEFAULT_PUT_WINDOW if self.version >= '02.12' else 1
        require(type(window) is int and 1 <= window <= MAX_PUT_WINDOW, 'invalid PUT window (1..16)')
        if timeout is None:timeout=getattr(self,'put_timeout',None)
        require(timeout is None or type(timeout) is int and 1<=timeout<=PUT_MAX_SECONDS,
                'invalid per-file PUT timeout (1..172800 seconds)')
        require(window == 1 or self.version >= '02.11', 'windowed PUT requires 02.11 or newer')
        self.require_transfer()
        dest = quoted_path(remote)
        expected = local if isinstance(local,wb_tree.FileSource) else None
        if expected is not None:
            require(snapshot is None,'snapshot supplied twice')
            local,snapshot=expected.path,expected.sig
        with wb_tree.checked_open(local,snapshot) as f, contextlib.ExitStack() as timers:
            st = os.fstat(f.fileno())
            require(stat.S_ISREG(st.st_mode) and (st.st_size>0 or (not image and self.version>='01.66'))
                    and st.st_size <= (PHOTO_MAX if image else LIMIT),
                    'local file exceeds limit or peer does not support an empty upload')
            size = st.st_size
            batch = auto_batch and size >= CHUNK*BATCH_FRAMES
            meter = TransferMeter()
            try:
                h = hashlib.sha256()
                seen = 0
                meter.update('HASH', 0, size)
                while (block := f.read(65536)):
                    seen += len(block)
                    require(seen <= size, 'source grew before upload')
                    h.update(block)
                    meter.update('HASH', seen, size)
                require(seen == size and wb_tree.signature(os.fstat(f.fileno()))==wb_tree.signature(st),
                        'source changed before transfer')
                sha = h.hexdigest()
                require(expected is None or (size==expected.size and sha==expected.sha256),
                        'source differs from approved snapshot')
                f.seek(0)
                if image:
                    suffix = Path(remote).suffix.lower()
                    raw = f.read(PHOTO_MAX+1)
                    require(valid_image(raw, suffix), 'expected complete JPEG/PNG matching device suffix')
                    f.seek(0)
                timing=timers.enter_context(_PutBudget(self,size,timeout))
                timing.arm()
                op = 'put-batch' if batch else 'put'
                ready = f'BATCH {size} {CHUNK} {BATCH_FRAMES}' if batch else f'PUT {size} {CHUNK}'
                self.command(f'{op} {dest} {size} sha256={sha}')
                require(self.reply() == 'TTY1 READY '+ready, 'unexpected put acknowledgement')
                timing.progress()
                meter.update('PUT', 0, size)
                sent = 0
                pending = deque()
                sent_digest = hashlib.sha256()
                while sent < size or pending:
                    if batch:
                        # Only locally generated decimal offsets and hex bytes. Never put
                        # user-supplied command text or filesystem names into a DATA group.
                        wire=bytearray()
                        for _ in range(BATCH_FRAMES):
                            want=min(CHUNK,size-sent)
                            if not want:break
                            data=f.read(want)
                            require(len(data)==want,'source truncated mid-transfer')
                            wire.extend(f'D {sent} {data.hex()}\n'.encode('ascii'))
                            sent+=want
                            sent_digest.update(data)
                        self._wire_write(bytes(wire))
                        require(self.reply()==f'TTY1 ACK {sent}','batch upload offset mismatch')
                        timing.progress()
                        meter.update('PUT',sent,size)
                        continue
                    while sent < size and len(pending) < window:
                        data = f.read(min(CHUNK, size-sent))
                        require(data, 'source truncated mid-transfer')
                        self.send(f'D {sent} {data.hex()}')
                        sent += len(data)
                        sent_digest.update(data)
                        pending.append(sent)
                    expected_pos = pending.popleft()
                    require(self.reply() == f'TTY1 ACK {expected_pos}', 'upload offset mismatch')
                    timing.progress()
                    meter.update('PUT', expected_pos, size)
                require(not f.read(1) and wb_tree.signature(os.fstat(f.fileno()))==wb_tree.signature(st)
                        and sent_digest.hexdigest()==sha,
                        'source changed during transfer')
                # END is never pipelined. A partial send or lost receipt after
                # attempting END is not evidence that publication failed.
                timing.commit()
                try:
                    self.send('END')
                    line=self.reply()
                    if line != f'TTY1 OK PUT {size} {sha}':
                        raise Inconclusive('put receipt did not match the sent content')
                    self.exact(getattr(self, 'root_prompt', ROOT_PROMPT))
                    timing.remaining()
                except DeviceRefused:
                    raise
                except Exception as exc:
                    raise Inconclusive('upload completion unknown: inspect destination, do not auto-retry') from exc
            finally:
                meter.finish()
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
        meter = TransferMeter()
        try:
            # Stage in the destination directory; publish exclusively only AFTER Vita's receipt.
            with tempfile.NamedTemporaryFile(dir=dest.parent, prefix='.wbterm-', suffix='.partial',delete=False) as out:
                stage = Path(out.name)
                self.command('get '+src)
                m = re.fullmatch(r'TTY1 READY GET (0|[1-9]\d{0,9}) 2048',self.reply())
                require(m and int(m[1]) <= min(max_bytes,LIMIT),'unexpected get size')
                size = int(m[1]); pos = 0; h = hashlib.sha256()
                meter.update('GET', 0, size)
                while pos < size:
                    self.send('NEXT '+str(pos))
                    r = re.fullmatch(r'TTY1 DATA (0|[1-9]\d{0,9}) ([0-9a-f]{2,4096})',self.reply())
                    require(r and int(r[1]) == pos and len(r[2])%2 == 0,'invalid download frame')
                    block = bytes.fromhex(r[2])
                    require(0 < len(block) <= size-pos,'download exceeds announced size')
                    out.write(block); h.update(block); pos += len(block)
                    meter.update('GET', pos, size)
                self.send('END'); sha = h.hexdigest()
                require(self.reply() == f'TTY1 OK GET {size} {sha}', 'download SHA-256/size mismatch')
                self.exact(getattr(self, 'root_prompt', ROOT_PROMPT))
                out.flush();os.fsync(out.fileno())
            os.link(stage,dest)  # Fails closed on existing destination or filesystems without hardlinks.
            return dict(action='get',remote=remote,local=str(dest.absolute()),bytes=size,sha256=sha)
        finally:
            meter.finish()
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
    for writer in (push,send):
        writer.add_argument('--timeout',type=put_timeout_arg,metavar='SECONDS',
                            help='per-file DATA time budget, 1..172800 (default size-aware); ACK idle 90s; END/readback has its own bounded deadline')
        writer.add_argument('--window',type=int,choices=range(1,MAX_PUT_WINDOW+1),metavar='1..16',
                            help='force legacy per-frame ACK PUT with this window; default on 02.14+ is batch ACK for files >=16 KiB')
    pull=commands.add_parser('pull',help='read one file via the terminal');pull.add_argument('remote');pull.add_argument('local')
    a=p.parse_args()
    try:
        if a.action=='read':read_command(a.args)
        if a.action=='send':batch=wb_tree.plan(a.sources,a.to,a.recursive,quoted_path)
        with paired_terminal() as t:
            if a.action in ('push','send'): t.put_window=a.window;t.put_timeout=a.timeout
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
