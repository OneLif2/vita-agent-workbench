"""Exercise the native PTY dispatch, identity bytes, promoter lifecycle and postconditions using stubs only."""
from pathlib import Path
import argparse, tempfile, subprocess, zipfile, hashlib
P=Path(__file__).resolve().parent; R=P.parents[1]; S=R/'source'
a=(S/'vita_ssh_status.c').read_text(); a=a[a.index('        case WB_CMD_TERM_SSH_VITA_STATUS:'):a.index('        case WB_CMD_TERM_FONT:')]
assert 'return wb_vita_ssh_vita_command' in a and 'cmd->argc!=1' in a
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--vpk',type=Path,default=R.parent/'external/ssh-vita/v1.4.2/upstream/ssh-vita.vpk',
                help='original upstream ssh-vita 1.4.2 release; read as data only')
ap.add_argument('--observe-hardware-signature',action='store_true',help='print simulated state transitions for the real negative-control tuple')
args=ap.parse_args();vpk=args.vpk
with tempfile.TemporaryDirectory() as tmp:
 t=Path(tmp);(t/'adapter.inc').write_text(a)
 assert hashlib.sha256(vpk.read_bytes()).hexdigest()=='e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce'
 with zipfile.ZipFile(vpk) as z:parts=[z.read(n) for n in ('sce_sys/param.sfo','eboot.bin')]
 for n,data,sha in zip(('sfo','boot'),parts,('49211daabc27fb7ff460f21aec7bb762cb476a85453318efb6094c0d7e3d3df3','bcf648cfa51588d44dca330049a67647c48db2f14300d093849c38efa7288f8c')):
  assert hashlib.sha256(data).hexdigest()==sha
  (t/n).write_bytes(data)
 exe=t/'probe.exe'
 subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(S),'-I'+str(R/'tests/stub'),'-I'+str(t),str(P/'fixture.c'),
  *[str(S/(n+'.c')) for n in ('wb_cmd','wb_out','wb_str','wb_shell','wb_sha256','wb_sfo')],'-o',str(exe)],check=True)
 subprocess.run([exe]+(['--observe-hardware-signature'] if args.observe_hardware_signature else []),cwd=t,check=True)
