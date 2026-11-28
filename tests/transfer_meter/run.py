"""Host transfer meter. No sockets, device, or install."""
import contextlib
import hashlib
import io
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'tools'))
import wbctl_pty
import wbterm as w


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Tty(io.StringIO):
    def isatty(self):
        return True


class Preload:
    """Response bytes are already buffered. Sends are recorded and not echoed again."""

    def __init__(self, body):
        self.data = bytearray(
            b'VITA AGENT TERMINAL 02.11 (Workbench)\r\nType help for commands.\r\nux0:/> ' + body)
        self.sent = []

    def recv(self, n):
        part = bytes(self.data[:n])
        del self.data[:len(part)]
        return part

    def recv_stderr_ready(self):
        return False

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, value):
        pass

    def exit_status_ready(self):
        return not self.data

    def recv_exit_status(self):
        return 0


class Scripted:
    def __init__(self, replies):
        self.buf = bytearray(b'VITA AGENT TERMINAL 01.66 (Workbench)\r\nType help for commands.\r\nux0:/> ')
        self.replies = list(replies)
        self.sent = []

    def recv(self, n):
        if not self.buf:
            raise AssertionError('scripted channel underrun')
        part = bytes(self.buf[:n])
        del self.buf[:len(part)]
        return part

    def recv_stderr_ready(self):
        return False

    def sendall(self, data):
        self.sent.append(data)
        text = data.decode('ascii')
        if text.startswith(('D ', 'NEXT ', 'END')):
            self.buf.extend(self.replies.pop(0))
        else:
            body = text[:-1] if text.endswith('\n') else text
            self.buf.extend(body.encode('ascii') + b'\r\n')
            if self.replies:
                self.buf.extend(self.replies.pop(0))

    def settimeout(self, value):
        pass

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0


def main():
    assert w.format_meter('PUT', 0, 100, '--', '--:--') == (
        'PUT [----------------------------]   0% 0 B/100 B -- ETA --:--')
    assert w.format_meter('PUT', 50, 100, '1.0 KB/s', '00:01') == (
        'PUT [##############--------------]  50% 50 B/100 B 1.0 KB/s ETA 00:01')
    assert w.format_meter('GET', 100, 100, '1.0 KB/s', '00:00').startswith(
        'GET [############################] 100%')
    hidden = w.format_meter('validate', 10, None, '--', '--:--')
    assert ' --%' in hidden and '/' not in hidden.split(']', 1)[1]
    assert w.format_eta(3661) == '01:01:01'
    assert w.format_qty(1536) == '1.5 KB' and w.format_rate(1536) == '1.5 KB/s'
    # The large-app host test keeps every non-tty progress line. The shortest
    # copy sample must stay long enough that 2400 of them exceed 64 KiB.
    assert sum(len(w.format_meter('copy', n, None, '--', '--:--')) + 1 for n in range(2400)) > 65536

    clock = Clock()
    tty = Tty()
    meter = w.TransferMeter(tty, clock)
    meter.update('HASH', 0, 2048)
    clock.now = 0.05
    meter.update('HASH', 1024, 2048)  # inside the 10 Hz tty interval
    assert tty.getvalue().count('\r') == 1
    clock.now = 1.0
    meter.update('HASH', 1024, 2048)
    meter.update('PUT', 1024, 2048)  # a phase change is a new line
    meter.finish()
    shown = tty.getvalue()
    assert shown.count('\n') == 2, shown
    assert shown.startswith('\rHASH ')
    assert '\n\rPUT ' in shown
    assert shown.endswith('\n')
    assert ' 50%' in shown and '1.0 KB/s' in shown and 'ETA 00:01' in shown

    plain = io.StringIO()
    log = w.TransferMeter(plain, clock)
    log.update('GET', 1, None)
    log.update('GET', 2, None)
    log.finish()
    text = plain.getvalue()
    assert text.count('\n') == 2 and '\r' not in text and ' --%' in text

    payload = b'abcd'
    sha = hashlib.sha256(payload).hexdigest()
    remote = 'ux0:/VITA-POC/a.bin'
    ready = f'TTY1 READY PUT {len(payload)} {w.CHUNK}\r\n'.encode()
    ack = f'TTY1 ACK {len(payload)}\r\n'.encode()
    ok = f'TTY1 OK PUT {len(payload)} {sha}\r\nux0:/> '.encode()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'a.bin'
        path.write_bytes(payload)
        channel = Scripted([ready, ack, ok])
        term = w.Terminal(channel)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            receipt = term.push(path, remote)
        assert receipt == dict(action='put', remote=remote, bytes=len(payload), sha256=sha)
        progress = err.getvalue()
        assert 'HASH ' in progress and 'PUT ' in progress and '%' in progress and 'ETA' in progress
        assert 'TTY1' not in progress
        assert sum(item.startswith(b'D ') for item in channel.sent) == 1
        assert channel.sent[-1] == b'END\n'

        got = Path(tmp) / 'out.bin'
        data_line = f'TTY1 DATA 0 {payload.hex()}\r\n'.encode()
        done = f'TTY1 OK GET {len(payload)} {sha}\r\nux0:/> '.encode()
        channel = Scripted([b'TTY1 READY GET 4 2048\r\n', data_line, done])
        term = w.Terminal(channel)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            pulled = term.pull(remote, got)
        assert pulled['sha256'] == sha and got.read_bytes() == payload
        assert 'GET ' in err.getvalue() and '100%' in err.getvalue()

    command = 'app-install "ux0:/VITA-POC/x.vpk"'
    receipt = b'OK app-install title=LARG12345 app_ver=01.00 files=3 detail=0 session=kept\r\n'
    body = (command.encode() + b'\r\n'
            + b'app-progress phase=copy bytes=0\r\n'
            + b'app-progress phase=copy bytes=50\r\n'
            + b'app-progress phase=validate bytes=10\r\n'
            + b'app-progress phase=extract bytes=25 total=100\r\n'
            + receipt + b'ux0:/> exit\r\nBye.\r\n')
    term = w.Terminal(Preload(body))
    term.install_total = 100
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        result = term._transcript_and_exit(command, 30)
    assert result['stdout'] == receipt.decode().replace('\r\n', '\n')
    assert result['progress'] == {
        'count': 4,
        'last': {'phase': 'extract', 'bytes': 25, 'total': 100},
    }
    log = err.getvalue()
    assert 'app-progress ' not in log
    assert 'copy [' in log and ' 50%' in log
    assert 'validate [' in log and ' --%' in log
    assert 'extract [' in log and ' 25%' in log

    # Each phase owns a different denominator. A completed generated head is
    # included in extract (100 archive bytes + WB_HEAD_SIZE=1072), not validate.
    exact = (command.encode() + b'\r\n'
             + b'app-progress phase=copy bytes=100 total=100\r\n'
             + b'app-progress phase=validate bytes=100 total=100\r\n'
             + b'app-progress phase=extract bytes=1172 total=1172\r\n'
             + receipt + b'ux0:/> exit\r\nBye.\r\n')
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        completed = w.Terminal(Preload(exact))._transcript_and_exit(command, 30)
    assert completed['progress'] == {
        'count': 3, 'last': {'phase': 'extract', 'bytes': 1172, 'total': 1172}}
    assert completed['stdout'] == receipt.decode().replace('\r\n', '\n')
    assert err.getvalue().count('100%') == 3

    # Zero/zero is representable without division by zero; nonzero/zero below
    # is impossible progress and must not be clamped to a false 100% receipt.
    empty = (command.encode() + b'\r\n'
             + b'app-progress phase=copy bytes=0 total=0\r\n'
             + receipt + b'ux0:/> exit\r\nBye.\r\n')
    with contextlib.redirect_stderr(io.StringIO()):
        zero = w.Terminal(Preload(empty))._transcript_and_exit(command, 30)
    assert zero['progress']['last'] == {'phase': 'copy', 'bytes': 0, 'total': 0}

    def refused(extra):
        peer = w.Terminal(Preload(command.encode() + b'\r\n' + extra))
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                peer._transcript_and_exit(command, 30)
        except w.Refused:
            return
        raise AssertionError('expected refusal')

    refused(b'app-progress phase=copy bytes=5 total=9\r\napp-progress phase=copy bytes=6\r\n')
    refused(b'app-progress phase=copy bytes=5 total=9\r\napp-progress phase=copy bytes=6 total=8\r\n')
    refused(b'app-progress phase=copy bytes=1 total=01\r\n')
    refused(b'app-progress phase=copy bytes=18446744073709551616\r\n')
    refused(b'app-progress phase=extract bytes=1072 total=1\r\n')
    refused(b'app-progress phase=copy bytes=1 total=0\r\n')
    refused(b'app-progress phase=validate bytes=10 total=9\r\n')
    refused(b'app-progress phase=extract bytes=18446744073709551615 total=18446744073709551614\r\n')

    rc, text = wbctl_pty.exchange('app-install ux0:/VITA-POC/x.vpk', 30, None, True)
    assert rc == 1 and 'invalid progress total' in text
    rc, text = wbctl_pty.exchange('app-install ux0:/VITA-POC/x.vpk', 30, None, 0)
    assert rc == 1 and 'invalid progress total' in text

    print('PASS transfer meter: bar, percent, rate, ETA, tty redraw, non-tty log, put/get, app-install percent')
    print('PASS old app-progress lines stay valid; total= is optional; copy can use the approved size; validate/extract do not invent a percent')
    print('PASS phase-specific exact totals (including generated head), zero/zero; reject byte overruns including nonzero/zero')
    print('HOST only: no socket, device, upload, or install')


if __name__ == '__main__':
    main()
