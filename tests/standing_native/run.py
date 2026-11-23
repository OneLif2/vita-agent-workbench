"""Exercise real private savedata and R1 integration with host stubs; no Vita."""
import subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
ROOT=D.parents[1]
def materialize(d):
    # Keep the same deterministic platform model as the original R1 test, but
    # add an independently readable private standing record and I/O failures.
    c=(ROOT/'tests/return_core/fixture.c').read_text(encoding='utf8')
    c=c[:c.index('static void tomb_or_error(')] # legacy assertions use a different target
    i=c.index('static void expect(');c=c[:i]+c[c.index('static void boot_env(',i):]
    c=c.replace('#include "wb_out.h"','#include "wb_out.h"\n#include "wb_cmd.h"\n#include "wb_r1_notice.h"')
    c=c.replace('const char *run_hex,*user_pin,*pin;} a;','const char *run_hex,*user_pin,*pin;uint32_t power_calls,power_event;bool power_latched;uint64_t rtc_last;} a;')
    c=c.replace('R1_LOCAL_PATH,WB_R1_INTENT,WB_R1_SUCCESS}', 'R1_LOCAL_PATH,WB_R1_INTENT,WB_R1_SUCCESS,WB_STANDING_PATH}')
    c=c.replace('files[3]','files[4]').replace('i<3;i++','i<4;i++')
    c=c.replace('static const char *const paths[]=', '#include "fixture_signature.inc"\n#include "wb_standing_vita.h"\nstatic const char *const paths[]=')
    c=c.replace('fail_remove;', 'fail_remove,fail_standing,lie_standing,unknown_standing,read_standing;')
    c=c.replace('if(!f->exists || cap<f->n', 'if((slot(p)==3&&read_standing) || !f->exists || cap<f->n')
    c=c.replace('if(fail_stat&&i==0)', 'if((unknown_standing&&i==3) || (fail_stat&&i==0))')
    c=c.replace('    assert(!s&&!m&&r&&n==1&&!strcmp(f->filePath,R1_NAME)&&f->bufSize==sizeof(r1_local));',
                '''    assert(!s&&!m&&r&&n==1);
    if(!strcmp(f->filePath,WB_STANDING_NAME)){
        assert(f->bufSize==sizeof(wb_standing_disk));
        if(fail_standing)return -1;
        return lie_standing?WB_OK:wq_save(WB_STANDING_PATH,f->buf,f->bufSize);
    }
    assert(!strcmp(f->filePath,R1_NAME)&&f->bufSize==sizeof(r1_local));''')
    c=c.replace('static const char *const oldrun', '''int wb_out_puts(wb_out *out,const char *s){return wb_out_printf(out,"%s",s);}
static const char *const oldrun''')
    (d/'fixture.c').write_text(c+(D/'native.c.in').read_text(encoding='utf8'),encoding='utf8')
def build(d,extra=None,*,bootstrap=True):
    out=d/'native.exe'
    cmd=['gcc','-std=c11','-Wall','-Wextra','-Werror',f'-DWB_STANDING_BOOTSTRAP={int(bootstrap)}']
    if extra:cmd+=extra
    cmd+=['-I'+str(d),'-I'+str(D),'-I'+str(ROOT/'tests/stub'),'-I'+str(ROOT/'tests/host_identity/sim'),
          '-I'+str(ROOT/'source'),str(d/'fixture.c'),str(ROOT/'source/wb_cmd.c'),'-o',str(out)]
    subprocess.run(cmd,cwd=d,check=True)
    return out
if __name__=='__main__':
    with tempfile.TemporaryDirectory() as t:
        d=Path(t);materialize(d);subprocess.run([str(build(d))],cwd=d,check=True)
        d=Path(t)/'shipping-no-bootstrap';d.mkdir()
        materialize(d);subprocess.run([str(build(d,bootstrap=False))],cwd=d,check=True)
