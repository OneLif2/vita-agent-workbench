"""Exercise the production client against an in-process byte-channel, with simulated latency.
No sockets, real waits, credentials, Vita or game writes. --probe accepts a copy
of an original, modified, or rolled-back client for an exact same-input comparison.
"""
import argparse, contextlib, hashlib, importlib.util, io, json, os, sys, tempfile
from collections import deque
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'tools'))
def load(file):
    spec=importlib.util.spec_from_file_location('budget_probe_client',file)
    w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
    return w
class Clock:
    def __init__(self):self.s=0.0
    def __call__(self):return self.s
class Channel:
    def __init__(self,clock,ack_s=.054,end_s=0,trickle=False):
        self.clock=clock;self.t=12;self.ack_s=ack_s;self.end_s=end_s;self.trickle=trickle
        self.q=deque([(0,b'VITA AGENT TERMINAL 02.11 (Workbench)\r\nType help for commands.\r\nux0:/> ')])
        self.wire=bytearray();self.hash=hashlib.sha256();self.acks=self.n=self.ended=self.commands=0
    def settimeout(self,t):self.t=t
    def gettimeout(self):return self.t
    def recv_stderr_ready(self):return False
    def recv(self,n):
        delay,b=self.q.popleft()
        if delay>self.t:
            self.clock.s+=self.t;raise TimeoutError('simulated socket timeout')
        self.clock.s+=delay;assert len(b)<=n;return b
    def send(self,b):
        self.sendall(b);return len(b)
    def sendall(self,b):
        self.wire.extend(b)
        while b'\n' in self.wire:
            i=self.wire.index(10);line=bytes(self.wire[:i]);del self.wire[:i+1]
            if line.startswith(b'put '):
                self.commands+=1;_,p,s,h=line.split()
                self.size=int(s);self.sha=h.split(b'=')[1]
                self.q.append((0,line+b'\r\nTTY1 READY PUT '+s+b' 2048\r\n'))
            elif line.startswith(b'D '):
                _,off,data=line.split()
                raw=bytes.fromhex(data.decode());assert self.n==int(off)
                self.n+=len(raw);self.hash.update(raw)
                self.acks+=1
                ack=b'TTY1 ACK '+str(self.n).encode()+b'\r\n'
                if self.trickle:self.q.extend((self.ack_s,bytes([byte])) for byte in ack)
                else:self.q.append((self.ack_s,ack))
            elif line==b'END':
                self.ended+=1;assert self.n==self.size and self.hash.hexdigest().encode()==self.sha
                self.q.append((self.end_s,b'TTY1 OK PUT '+str(self.n).encode()+b' '+self.sha+b'\r\nux0:/> '))
            elif line==b'pwd':self.q.append((0,b'pwd\r\nux0:/\r\nux0:/> '))
            else:raise AssertionError(line)
class NoMeter:
    def update(self,*args):pass
    def finish(self):pass
def run(w,file,*,ack=.054,end=0,trickle=False,arg=None,outer=None):
    clk=Clock();ch=Channel(clk,ack,end,trickle);rc='OK';why=''
    with mock.patch.object(w.time,'monotonic',clk),mock.patch.object(w,'TransferMeter',NoMeter):
        t=w.Terminal(ch)
        if outer is not None:t.deadline=outer
        try:res=t.push(file,'ux0:/VITA-POC/t.bin',**({'timeout':arg} if arg is not None else {}))
        except Exception as e:rc=type(e).__name__;why=str(e);res=None
        if rc=='OK':assert t.one('pwd')=='ux0:/'
    return dict(status=rc,reason=why,commands=ch.commands,frames=ch.acks,end=ch.ended,original_channel_timeout_restored=ch.t==12,
                custom_deadline_restored=outer is None or t.deadline==outer,remaining_shell_seconds=round(t.deadline-clk.s,3),
                virtual_s=round(clk.s,3),receipt=res)
def main():
    p=argparse.ArgumentParser();p.add_argument('--client',type=Path,default=ROOT/'tools/wbterm.py');p.add_argument('--probe',action='store_true')
    a=p.parse_args();w=load(a.client)
    with tempfile.TemporaryDirectory(prefix='wb-timeout-') as d:
        file=Path(d)/'fixture.bin'
        with file.open('xb') as f:f.truncate(192*1024*1024)
        r=run(w,file);print(json.dumps(r,sort_keys=True))
        if a.probe:return
        assert r['status']=='OK' and r['virtual_s']>=86*60 and r['frames']==98304 and r['end']==1
        assert r['original_channel_timeout_restored'] and r['remaining_shell_seconds']==1800
        file.write_bytes(b'AB'*2048)
        # A coherent 2s data budget should still allow a separate native readback.
        r=run(w,file,ack=.6,end=80,arg=2)
        assert r['status']=='OK' and r['end']==1 and r['virtual_s']==81.2
        for options,error,ended in [
              ({'ack':.6,'arg':1},'TimeoutError',0),({'ack':95,'arg':7200},'TimeoutError',0),
              ({'ack':10,'trickle':True,'arg':7200},'TimeoutError',0),
              ({'end':121,'arg':7200},'Inconclusive',1),({'outer':1,'end':3},'Inconclusive',1),
              ({'arg':0},'Refused',0),({'arg':172801},'Refused',0)]:
            r=run(w,file,**options)
            assert (r['status'],r['end'])==(error,ended),r
            assert r['original_channel_timeout_restored'] and r['custom_deadline_restored'] and r['commands']<2,r
            if ended:assert 'do not auto-retry' in r['reason']
        for action in ['push','send']:
            argv=['wbterm',action,str(file)]+(['ux0:/VITA-POC/t.bin'] if action=='push' else ['--to','ux0:/VITA-POC'])
            peer=mock.Mock()
            with mock.patch.object(w,'paired_terminal',return_value=contextlib.nullcontext(peer)),mock.patch.object(w.wb_tree,'plan'),mock.patch.object(w.wb_tree,'send',return_value={}),mock.patch.object(sys,'argv',argv+['--timeout','7200']),contextlib.redirect_stdout(io.StringIO()):
                peer.push.return_value={};assert w.main()==0;assert peer.put_timeout==7200
            with mock.patch.object(sys,'argv',argv+['--timeout','172801']),mock.patch.object(w,'paired_terminal') as connect,contextlib.redirect_stderr(io.StringIO()):
                try:w.main()
                except SystemExit as e:assert e.code==2
                else:raise AssertionError('CLI allowed unbounded timeout')
                connect.assert_not_called()
    print('PASS 02.11 peer, 88+ min simulated progress, size-aware and override totals, ACK idle, trickle stall, separate END verification, no retry, caller deadline/socket restoration, both CLI forms.')
if __name__=='__main__':main()
