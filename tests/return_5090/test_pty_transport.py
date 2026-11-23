"""Use the actual R1 receipt parser over a fragmented shell stream. No Vita."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import r1ctl,wbterm
class C:
    def __init__(self):self.queue=bytearray(b'VITA AGENT TERMINAL 01.65 (Workbench)\r\nType help for commands.\r\nux0:/> ');self.rx=b'';self.cmds=[]
    def recv(self,_):
        v=bytes(self.queue[:3]);del self.queue[:3];return v
    def sendall(self,b):self.cmds.append(bytes(b));self.queue.extend(b.strip()+b'\r\n'+self.rx)
    def recv_stderr_ready(self):return False
class Tests(unittest.TestCase):
    def test_same_shell_commands(self):
        ch=C();s=r1ctl.Session([]);s.term=wbterm.Terminal(ch);s.sid='one'
        ch.rx=b'pending-core: WBQ2 receipt\r\n\r\nux0:/> '
        self.assertEqual(s.cmd('pending'),(0,'pending-core: WBQ2 receipt'))
        grant='apply-return '+'3'*32
        ch.rx=b'ERR R1 grant-required; no updater launched\r\nux0:/> '
        self.assertEqual(s.cmd(grant)[0],1)
        ch.rx=b'OK updater installed (detail=0), launching INAP00019; ssh will drop\r\nux0:/> '
        self.assertEqual(s.cmd(grant)[0],0)
        for label,detail,allowed in [('reused',1,True),('reused',0,False),('installed',1,False),('installed',-1,False)]:
            ch.rx=f'OK updater {label} (detail={detail}), launching INAP00019; ssh will drop\r\nux0:/> '.encode()
            if allowed: self.assertEqual(s.cmd(grant)[0],0)
            else:
                with self.assertRaises(r1ctl.Stop): s.cmd(grant)
        ch.rx=b'OK not-an-updater-receipt\r\nux0:/> '
        with self.assertRaises(r1ctl.Stop):s.cmd(grant)
        with self.assertRaises(r1ctl.Stop):s.cmd('apply-core')
        self.assertEqual(len(ch.cmds),8)
if __name__=='__main__':unittest.main()
