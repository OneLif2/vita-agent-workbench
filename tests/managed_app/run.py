"""Compile real shell/native code under syscall stubs. --observe --root accepts a release tree with source/."""
from pathlib import Path
import argparse,subprocess,tempfile,hashlib,zipfile,sys
P=Path(__file__).resolve().parent; R=P.parents[1]
def main():
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--root',type=Path,default=R);a.add_argument('--observe',action='store_true');o=a.parse_args()
 src=o.root.resolve()/'source';legacy=not (src/'wb_managed_app.inc').exists();gcc=['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2']
 with tempfile.TemporaryDirectory() as td:
  t=Path(td);exe=t/'fixture.exe'
  if legacy:
   if not o.observe:raise AssertionError('expected candidate')
   (t/'fixture.c').write_text('''#include "wb_shell.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
static int sub(void *c,const wb_cmd *d,wb_out *out){(void)c;(void)d;(void)out;assert(0);return 1;}
static int wr(void*c,const char*d,size_t n){(void)c;fwrite(d,1,n,stdout);return 0;}
int main(void){wb_shell_engine e;wb_shell_init(&e);wb_shell_ops o={.core_exec=sub};wb_out w={NULL,wr};wb_shell_run(&e,"app status INAP00020",&w,&o);wb_shell_run(&e,"app uninstall-plan INAP00020",&w,&o);puts("delete calls=0 disk=1 registry=1; refused in PTY, not submitted");}''')
  else:
   base=R.parent/'v1.73/build/testapp.vpk'
   assert hashlib.sha256(base.read_bytes()).hexdigest()=='fea70dc69399200bdf00ca145044cac7725b4987d19da9d032ff2dbfd12a43e9'
   with zipfile.ZipFile(base) as z:
    sfo=z.read('sce_sys/param.sfo');boot=z.read('eboot.bin')
   (t/'sfo').write_bytes(sfo);(t/'boot').write_bytes(boot)
   c=(R/'tests/ssh_vita_uninstall/fixture.c').read_text();c=c[:c.index('int main(int argc,char**argv)')]
   c=c.replace('#include "wb_ssh_vita_uninstall.inc"', '''#include "wb_ssh_vita_uninstall.inc"
#include "wb_managed_app.inc"
#include "wb_ssh.h"
#include "wb_shell_channel.h"
static wb_ssh g_ssh;
#define TESTID "INAP00020"
static const struct {char run_hex[17];} a={"0123456789ABCDEF"};
static int alt,system_shadow;
static uint64_t clock_us;uint64_t sceKernelGetProcessTimeWide(void){return clock_us;}
static const char *map(const char*p){return alt&&strstr(p,"ABCD00001")?"ABCD00001":"INAP00020";}''')
   c=c.replace('sfo[912],boot[181097]',f'sfo[{len(sfo)}],original[{len(sfo)}],boot[{len(boot)}]')
   c=c.replace('!strcmp(id,WBU_ID)','!strcmp(id,map(id))').replace('!strcmp(p,WBU_ID)','!strcmp(p,map(p))')
   c=c.replace('assert(!strcmp(p,WBU_ROOT)', '''if(!strncmp(p,"vs0:/app/",9)){st->st_mode=0x1000;return system_shadow>0?0:system_shadow<0?-9:WBU_NOTFOUND;}
 assert(!strcmp(p,WBU_ROOT)''')
   for m,suffix in [('WBU_ROOT',''),('WBU_BOOT','/eboot.bin'),('WBU_SFO','/sce_sys/param.sfo')]:
    c=c.replace('strcmp(p,'+m+')','strcmp(p,(alt?"ux0:/app/ABCD00001'+suffix+'":"ux0:/app/INAP00020'+suffix+'"))')
   c=c.replace('?912:181097','?sizeof sfo:sizeof boot')
   c+='#define EXPECTED_SFO "'+hashlib.sha256(sfo).hexdigest()+'"\n#define EXPECTED_BOOT "'+hashlib.sha256(boot).hexdigest()+'"\n'+(P/'managed.c.in').read_text()
   dispatch=(src/'vita_ssh_status.c').read_text()
   a=dispatch.index('        case WB_CMD_TERM_USER_STATUS:');b=dispatch.index('        case WB_CMD_TERM_FONT:',a);(t/'adapter.inc').write_text(dispatch[a:b])
   (t/'fixture.c').write_text(c)
  subprocess.run(gcc+['-I'+str(src),'-I'+str(R/'tests/stub'),'-I'+str(t),str(t/'fixture.c')]+[str(src/(x+'.c')) for x in ('wb_shell','wb_shell_channel','wb_cmd','wb_out','wb_str','wb_sha256','wb_sfo')]+['-o',str(exe)],check=True,cwd=t)
  subprocess.run([str(exe)]+(['observe'] if o.observe else []),check=True,cwd=t)
if __name__=='__main__':main()
