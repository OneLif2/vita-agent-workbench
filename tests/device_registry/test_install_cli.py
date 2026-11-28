"""Host-only: the 5090 install client dispatches only a verified package and
requires exact title/version receipts. No Vita, filesystem changes or sockets."""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import wbctl

VPK=ROOT.parent/"external/ssh-vita/v1.4.2/upstream/ssh-vita.vpk"
SHA="e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce"

class InstallOnly(unittest.TestCase):
    def run_cli(self, args, **reply):
        commands=[]
        def exchange(command, **kwargs):
            commands.append(command)
            if len(commands)==1:
                op,path,n,digest=command.split()
                self.assertEqual((op,n,digest),("put","311546","sha256="+SHA))
                self.assertRegex(path,r"^ux0:/VITA-POC/VSSH00001-e6363e62-[a-f0-9]{12}\.vpk$")
                source=kwargs["stdin_bytes"]
                self.assertIsInstance(source,wbctl.wb_tree.FileSource)
                self.assertEqual(source.path.read_bytes(),VPK.read_bytes())
                return reply.get("put_rc",0),f"OK put path={path} bytes={n} sha256="+reply.get("digest",SHA)
            self.assertEqual(len(commands),2)
            self.assertEqual(command, "app-install "+commands[0].split()[1])
            return reply.get("rc",0),"OK app-install title="+reply.get("title","VSSH00001")+" app_ver="+reply.get("ver","01.42")+" files=11 detail=0 session=kept"
        with patch.object(wbctl,"ssh",exchange),contextlib.redirect_stdout(io.StringIO()):
            rc=wbctl.main(args)
        return rc,commands

    def test_plan_dry_run_and_case_denial_never_send(self):
        for args,want in [(["app","plan",str(VPK)],0),
                          (["app","install",str(VPK)],0),
                          (["app","install",str(VPK),"--case","fs-smoke","--yes"],2),
                          (["test","run","fs-smoke","--vpk",str(VPK)],2)]:
            with self.subTest(args=args): self.assertEqual(self.run_cli(args),(want,[]))

    def test_exact_receipts_and_no_launch(self):
        for reply,want,count in [({},0,2),({"title":"INAP00020"},5,2),
                                 ({"ver":"01.43"},5,2),({"rc":1},5,2),
                                 ({"put_rc":1},4,1),({"digest":"0"*64},4,1)]:
            with self.subTest(reply=reply):
                rc,cmds=self.run_cli(["app","install",str(VPK),"--yes"],**reply)
                self.assertEqual((rc,len(cmds)),(want,count))

if __name__=="__main__": unittest.main(verbosity=2)
