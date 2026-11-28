"""Exercise production Terminal.push on an in-memory PTY byte channel; no SSH, devices or sleeps."""
import argparse, collections, hashlib, importlib.util, json, os, re, sys, tempfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
CHUNK=2048; GROUP=8
NAME='ux0:/VITA-POC/batch fixture.bin'

def load(path):
    spec=importlib.util.spec_from_file_location('probe_wbterm',path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

class Meter:
    def update(self,*args):pass
    def finish(self):pass

class BytePeer:
    def __init__(self,src,ver,fault=None,short=False):
        self.src=src;self.data=src.read_bytes()
        self.clock=0;self.timeout=12;self.t0=12
        self.q=collections.deque()
        self.wire=bytearray();self.ops=[];self.frames=0;self.acks=[];self.end=0
        self.active=False;self.size=0;self.hash=None;self.done=0;self.unacked=0
        self.sendcalls=0;self.data_sends=0;self.fault=fault;self.short=short
        self.reply(f'VITA AGENT TERMINAL {ver} (Workbench)\r\nType help for commands.\r\nux0:/> ')
    def settimeout(self,t):self.timeout=t
    def gettimeout(self):return self.timeout
    def recv_stderr_ready(self):return False
    def reply(self,s,delay=0):self.q.append([s.encode('ascii'),delay])
    def recv(self,n):
        if not self.q:return b''
        raw,delay=self.q.popleft()
        if delay>self.timeout:
            self.clock+=self.timeout;raise TimeoutError('no progress')
        self.clock+=delay
        if len(raw)>n:self.q.appendleft((raw[n:],0))
        return raw[:n]
    def send(self,wire):
        partial=wire[:871] if self.short else wire
        self.sendcalls+=1
        if self.active and partial!=b'END\n': self.data_sends+=1
        self.wire.extend(partial)
        while b'\n' in self.wire:
            i=self.wire.index(10);line=bytes(self.wire[:i]);del self.wire[:i+1]
            if not self.active:
                m=re.fullmatch(rb'(put(?:-batch)?) "ux0:/VITA-POC/batch fixture.bin" (\d+) sha256=([0-9a-f]{64})',line)
                assert m,line
                self.ops.append(m[1].decode());self.active=True;self.size=int(m[2]);self.hash=hashlib.sha256()
                assert self.size==len(self.data) and m[3].decode()==hashlib.sha256(self.data).hexdigest()
                ready=(f'BATCH {self.size} 2048 8' if self.ops[-1]=='put-batch' else f'PUT {self.size} 2048')
                if self.fault=='bad_ready':ready=ready.replace('2048','4096')
                self.reply(line.decode()+'\r\nTTY1 READY '+ready+'\r\n')
            elif line==b'END':
                self.end+=1;assert self.done==self.size and self.unacked==0
                assert self.hash.hexdigest()==hashlib.sha256(self.data).hexdigest()
                self.active=False
                if self.fault=='lost_end':continue
                h='0'*64 if self.fault=='wrong_hash' else self.hash.hexdigest()
                self.reply(f'TTY1 OK PUT {self.done} {h}\r\nux0:/> ',121 if self.fault=='late_end' else 0)
            else:
                m=re.fullmatch(rb'D (\d+) ([0-9a-f]+)',line);assert m,line
                assert int(m[1])==self.done
                raw=bytes.fromhex(m[2].decode());assert len(raw)==min(CHUNK,self.size-self.done)
                assert raw==self.data[self.done:self.done+len(raw)]
                self.hash.update(raw);self.done+=len(raw);self.frames+=1;self.unacked+=1
                if self.frames==3 and self.fault=='send_lost': raise ConnectionError('group send interrupted')
                if self.ops[-1]=='put-batch' and self.unacked<GROUP and self.done!=self.size:continue
                self.acks.append(self.done);self.unacked=0
                if self.fault=='lost_ack':continue
                if self.fault=='refused_write':
                    self.reply('TTY1 ERR write-error\r\n');continue
                off=self.done-1 if self.fault=='wrong_ack' else self.done
                if self.fault=='mutated' and len(self.acks)==1:
                    st=self.src.stat();os.utime(self.src,ns=(st.st_atime_ns,st.st_mtime_ns+10_000_000_000))
                self.reply(f'TTY1 ACK {off}\r\n',91 if self.fault=='stalled' else 0)
        return len(partial)

def run(w,p,ver='02.14',win=None,fault=None,short=False):
    peer=BytePeer(p,ver,fault,short);receipt=None;error=''
    with patch.object(w.time,'monotonic',lambda:peer.clock),patch.object(w,'TransferMeter',Meter):
        t=w.Terminal(peer)
        try:receipt=t.push(p,NAME,window=win)
        except AssertionError:raise
        except Exception as e:error=type(e).__name__+': '+str(e)
        assert peer.gettimeout()==peer.t0
    return dict(ops=peer.ops,frames=peer.frames,acknowledgements=len(peer.acks),last_offset=peer.acks[-1] if peer.acks else 0,
                data_send_calls=peer.data_sends,ends=peer.end,receipt=receipt,error=error)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--client',type=Path,default=ROOT/'tools/wbterm.py');ap.add_argument('--probe',action='store_true')
    a=ap.parse_args();w=load(a.client)
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/'fixture.bin'
        data=bytes(range(256))*4096+b'tail-0214';p.write_bytes(data)
        r=run(w,p);print(json.dumps(r,sort_keys=True))
        if a.probe:return
        assert r['ops']==['put-batch'] and r['acknowledgements']==65 and r['frames']==513 and r['data_send_calls']==65
        for n in (0,1,16383,16384,16385,32768,32769):
            p.write_bytes(data[:n]);r=run(w,p)
            batch=n>=16384
            assert r['ops']==['put-batch' if batch else 'put'] and not r['error'] and r['ends']==1,r
            assert r['acknowledgements']==(n+(16384 if batch else CHUNK)-1)//(16384 if batch else CHUNK)
            assert (r['receipt']['bytes'],r['receipt']['sha256'])==(n,hashlib.sha256(data[:n]).hexdigest())
        for ver,window in [('02.11',None),('02.12',None),('02.13',None),('02.14',1),('02.14',8),('02.14',16)]:
            r=run(w,p,ver,window);assert r['ops']==['put'] and r['acknowledgements']==17 and not r['error'],r
        r=run(w,p,short=True);assert not r['error'] and r['ends']==1 and r['data_send_calls']>3
        for f,cls,ended in [('bad_ready','Refused',0),('wrong_ack','Refused',0),('lost_ack','Inconclusive',0),
                 ('refused_write','DeviceRefused',0),('stalled','TimeoutError',0),('send_lost','ConnectionError',0),
                 ('mutated','Refused',0),('lost_end','Inconclusive',1),('late_end','Inconclusive',1),('wrong_hash','Inconclusive',1)]:
            r=run(w,p,fault=f)
            assert r['error'].startswith(cls+':') and r['ends']==ended and r['ops']==['put-batch'] and r['receipt'] is None,(f,r)
    print('PASS batch threshold / exact and partial groups / old peers / explicit legacy windows / short SSH send / bad or missing replies / changed source / stalled or ambiguous END. No device.')
if __name__=='__main__':main()
