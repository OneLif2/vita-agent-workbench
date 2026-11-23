"""5090 client for an explicitly enabled WB-only receiver. No discovery, TOFU or retry.

The lifecycle test VPK is NOT this receiver. Without independently enrolled
receiver identity the command stops locally, rather than trying other services.
"""
from __future__ import annotations
import contextlib, hashlib, hmac, json, re, socket, sys, threading, time
from pathlib import Path
import wbterm as wb

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT, USER = wb.HOST, 2224, 'pi'
VERB = 'wb open'
SHA = re.compile('[0-9a-f]{64}')
REPLIES = {b'WAKE1 DISPATCHED_UNVERIFIED\n':0, b'WAKE1 ALREADY_RUNNING\n':0,
           b'WAKE1 DENIED\n':125, b'WAKE1 NEEDS_OWNER\n':126, b'WAKE1 PLATFORM_ERROR\n':1}

def fp(k): return hashlib.sha256(k.asbytes()).hexdigest()

def validate(p, wb_pin):
    if not isinstance(p,dict) or set(p)!= {'schema','wb_sha256','receiver_sha256','owner_sha256'}:
        raise ValueError('bad independent receiver enrollment')
    if (p['schema']!='wb.wake.local-enrollment.v1' or p['wb_sha256']!=wb_pin or
        any(not isinstance(p[k],str) or not SHA.fullmatch(p[k]) or int(p[k],16)==0 for k in ('wb_sha256','receiver_sha256','owner_sha256')) or
        len({p['wb_sha256'],p['receiver_sha256'],p['owner_sha256']})!=3):
        raise ValueError('distinct verified WB, receiver, and owner identities required')
    return p

def exchange(addr,p,owner_loader,mark):
    """One pinned SSH exec, no PTY/interactive shell, forwarding or command arguments."""
    import paramiko
    with socket.create_connection(addr,timeout=4) as sock:
        def expire():
            with contextlib.suppress(OSError): sock.shutdown(socket.SHUT_RDWR)
        timer=threading.Timer(10,expire);timer.daemon=True;timer.start()
        try:
            with paramiko.Transport(sock) as t:
                t.banner_timeout=t.auth_timeout=t.channel_timeout=4
                t.get_security_options().key_types=('ecdsa-sha2-nistp256',)
                t.start_client(timeout=4)
                key=t.get_remote_server_key()
                if not hmac.compare_digest(fp(key),p['receiver_sha256']):raise ValueError('wrong receiver host key; no owner auth')
                owner=owner_loader()
                if owner.get_name()!='ecdsa-sha2-nistp256' or not hmac.compare_digest(fp(owner),p['owner_sha256']):
                    raise ValueError('wrong owner key')
                t.auth_publickey(USER,owner)
                if not t.is_authenticated():raise ValueError('owner not authenticated')
                with t.open_session(timeout=4) as ch:
                    ch.settimeout(4)
                    sid=hashlib.sha256(bytes(t.session_id)).hexdigest()
                    mark(sid)  # durable one-attempt record before the first actionable byte
                    ch.exec_command(VERB); ch.shutdown_write()
                    out=bytearray()
                    while True:
                        b=ch.recv(96)
                        if not b: break
                        out.extend(b)
                        if len(out)>80:raise ValueError('oversized receiver reply')
                    code=ch.recv_exit_status();raw=bytes(out)
                    if ch.recv_stderr_ready() or REPLIES.get(raw)!=code:raise ValueError('unverified receiver reply')
                    return raw.decode('ascii').strip().split(' ')[1], sid
        finally:timer.cancel()

def open_wb():
    sys.path.insert(0,str(ROOT/'wake-acceptance'))
    import verify as verify
    state = dict(launch_sent=False, causal_pass=False)
    marker_created=False
    try:
        anchor=verify.anchor();verify.saved_pin_matches(anchor)
        profile=Path.home()/'.ssh'/'wb-wake.local.json'
        try:
            with wb.paired_terminal() as tty:
                if tty.host_pin!=anchor['host_pin']:raise ValueError('WB identity changed')
                current=tty.check()
            return 0,dict(state,status='ALREADY_RUNNING',run=current['run'])
        except ConnectionRefusedError:pass  # not proof that the process is closed
        except TimeoutError:
            return 3,dict(state,status='WB_TIMEOUT_RECEIVER_NOT_CONTACTED',receiver_enrolled=profile.is_file())
        if not profile.exists():return 3,dict(state,status='NO_ENROLLED_RECEIVER')
        with profile.open('rb') as f:data=f.read(2049)
        if len(data)>2048:raise ValueError('oversized receiver enrollment')
        enroll=validate(json.loads(data),anchor['host_pin'])
        samples=sorted((ROOT/'wake-acceptance/evidence').glob('DEVICE-*.json'),reverse=True)
        baseline=None
        for f in samples:
            record=json.loads(f.read_bytes())
            if record.get('phase')=='before' and record.get('result')==verify.BEFORE:
                baseline=verify.load_baseline(f,anchor);break
        if not baseline:return 3,dict(state,status='PRECLOSE_OBSERVATION_REQUIRED')
        old=baseline['identity']['run'];record=ROOT/'wake-acceptance/evidence'/('ISSUED-'+old+'.json')
        if record.exists():return 3,dict(state,status='PRIOR_ATTEMPT_DO_NOT_RETRY',old_run=old)
        def mark(sid):
            import os
            nonlocal marker_created
            with record.open('x',encoding='utf8') as fd:
                marker_created=True
                json.dump(dict(utc_unix=time.time(),old_run=old,transport_sha256=sid,receiver_sha256=enroll['receiver_sha256'],
                               baseline_sha256=baseline['sha256'],command=VERB),fd);fd.flush();os.fsync(fd.fileno())
        def load_owner():
            import paramiko,os
            return paramiko.ECDSAKey.from_private_key_file(str(Path(os.getenv('WB_KEY',str(Path.home()/'.ssh/id_ecdsa_wb')))))
        status,sid=exchange((HOST,PORT),enroll,load_owner,mark)
        ack=dict(status=status,request_sent=True,launch_sent=(status=='DISPATCHED_UNVERIFIED'),
                 causal_pass=False,old_run=old,transport_sha256=sid,utc_unix=time.time(),
                 receiver_sha256=enroll['receiver_sha256'],baseline_sha256=baseline['sha256'])
        with record.with_name('REPLY-'+old+'.json').open('x',encoding='utf8') as f:json.dump(ack,f)
        return (0 if status in ('DISPATCHED_UNVERIFIED','ALREADY_RUNNING') else 3),ack
    except Exception as exc:
        return 2,dict(state,status='INCONCLUSIVE_NO_RETRY' if marker_created else 'NOT_DISPATCHED',
                      launch_sent=None if marker_created else False,reason=type(exc).__name__+': '+str(exc)[:180])
