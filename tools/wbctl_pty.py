"""Finite translation table for wbctl. No command here can open an SSH exec/subsystem."""
import hashlib,math,re,socket,tempfile,time
from pathlib import Path
import wbterm as t

HEX=r'[0-9a-f]{64}'
NAME=r'[A-Za-z0-9_.@()+-]{1,100}'
IN=r'ux0:/VITA-POC/'+NAME
DIAG={'get ux0:data/INAP00018/timeline.txt':('ux0:/data/INAP00018/timeline.txt',2*1024*1024),
      'get ux0:data/INAP00018/testapp/result.txt':('ux0:/data/INAP00018/testapp/result.txt',1024)}

def text_command(c):
    if c in ('ver','status','help','timeline','pending','apply-core','ver unexpected-argument'):
        return c
    if re.fullmatch(r'df (0|[1-9]\d{0,19})',c):return c
    for verb in ('inspect','ext stat','app-install'):
        m=re.fullmatch(re.escape(verb)+r' ('+IN+r')',c)
        if m:return verb+' '+t.quoted_path(m[1])
    for verb,flag in (('install','sha256='),('photo-export','')):
        m=re.fullmatch(verb+r' ('+IN+r') '+flag+'('+HEX+')',c)
        if m:return verb+' '+t.quoted_path(m[1])+' '+flag+m[2]
    if re.fullmatch(r'launch INAP00020 (?:fs-smoke|compute-smoke|power-smoke) [0-9]{8}T[0-9]{6}-[0-9a-f]{12}',c):
        return c
    raise t.Refused('not an admitted wbctl terminal operation')

def exchange(cmd,timeout,stdin_bytes,progress_total=None):
    try:
        t.require(isinstance(cmd,str) and len(cmd)<512 and math.isfinite(timeout) and timeout>0,'invalid PTY request')
        if progress_total is not None:
            t.require(type(progress_total) is int and 0<progress_total<=t.LIMIT,'invalid progress total')
        upload=re.fullmatch(r'put ('+IN+r') ([1-9]\d{0,9}) sha256=('+HEX+')',cmd)
        t.require(timeout<=600 or upload or cmd.startswith('app-install '),'invalid PTY request timeout')
        diag=DIAG.get(cmd)
        if upload:
            remote,size,sha=upload[1],int(upload[2]),upload[3]
            t.quoted_path(remote)
            t.require(size<=t.LIMIT,'upload exceeds Vita uint32 file limit')
            if isinstance(stdin_bytes,t.wb_tree.FileSource):
                t.require((stdin_bytes.size,stdin_bytes.sha256)==(size,sha),'upload snapshot differs from request')
                with t.wb_tree.checked_open(stdin_bytes.path,stdin_bytes.sig) as file:
                    t.require(t.wb_tree.file_digest(file,size)==sha,'upload bytes differ from request')
            else:
                t.require(isinstance(stdin_bytes,bytes) and len(stdin_bytes)==size and t.digest(stdin_bytes)==sha,'upload bytes differ from request')
        elif stdin_bytes is not None:
            raise t.Refused('unexpected stdin')
        elif not diag:
            wire=text_command(cmd)
        with t.paired_terminal() as term:
            if progress_total is not None:
                term.install_total=progress_total
            term.deadline=(time.monotonic()+timeout if upload or cmd.startswith('app-install ')
                           else min(term.deadline,time.monotonic()+timeout))
            if upload:
                if isinstance(stdin_bytes,t.wb_tree.FileSource):
                    # The caller retains this private snapshot context until receipt.
                    r=term.push(stdin_bytes,remote)
                else:
                    # Compatibility only for existing bounded small CORE/Photos callers.
                    with tempfile.TemporaryDirectory() as tmp:
                        p=Path(tmp)/'input';p.write_bytes(stdin_bytes)
                        r=term.push(p,remote)
                t.require(r['sha256']==sha and r['bytes']==size and r['remote']==remote,'invalid published receipt')
                return 0,f'OK put path={remote} bytes={size} sha256={sha}'
            if diag:
                remote,cap=diag
                with tempfile.TemporaryDirectory() as tmp:
                    p=Path(tmp)/'diagnostic';r=term.pull(remote,p,max_bytes=cap);b=p.read_bytes()
                    t.require(0<=len(b)==r['bytes']<=cap and t.digest(b)==r['sha256'],'diagnostic digest mismatch')
                    return 0,b.decode('ascii').replace('\r\n','\n').strip()
            try:
                r=term._transcript_and_exit(wire,timeout)
            except t.Refused:
                # A truncated/invalid echo, footer or exit status is not a refusal
                # from the Vita. This matters if an app transition actually ran.
                return 255,'UNKNOWN terminal transcript incomplete or contradictory'
            out=r['stdout'].strip()
            # The shell only exposes a channel-level exit at EOF. A text-level rejection
            # is nonzero; never forge an SSH per-command exit status for a PTY.
            return (1 if any(x.startswith('ERR ') for x in out.splitlines()) else 0),out
    except (t.pin.PairError,t.TrustRefused) as e:return 78,'ERR SSH trust: '+str(e)
    except (socket.timeout,TimeoutError):return 124,'TIMEOUT waiting for terminal receipt'
    except t.Refused as e:return 1,'ERR terminal: '+str(e)
    except t.wb_tree.TreeError as e:return 1,'ERR local-source: '+str(e)
    except (t.Inconclusive,EOFError,ConnectionError,OSError) as e:
        return 255,'UNKNOWN terminal disconnected or unavailable: '+type(e).__name__
    except ImportError:return 127,'Paramiko unavailable; no alternate transport used'
    except Exception as e:
        return 255,'UNKNOWN terminal not confirmed: '+type(e).__name__
