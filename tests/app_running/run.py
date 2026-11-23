"""Compile actual inventory module, shell and parser against SDK declarations."""
from pathlib import Path
import os,subprocess,tempfile
D=Path(__file__).resolve().parent
S=D.parents[1]/'source'
def build(t,shell=None,header=None):
    t.mkdir(exist_ok=True)
    (t/'psp2').mkdir(exist_ok=True)
    (t/'psp2/appmgr.h').write_text('''#ifndef FIXTURE_APPMGR_H
#define FIXTURE_APPMGR_H
#include <stdint.h>
typedef int32_t SceInt32;
typedef int32_t SceUID;
typedef uint32_t SceSize;
/* Published SceAppMgr error names, copied from the pinned SDK header. */
typedef enum SceAppMgrErrorCode {
 SCE_APPMGR_ERROR_BUSY=0x80802000, SCE_APPMGR_ERROR_STATE=0x80802013,
 SCE_APPMGR_ERROR_NOT_FOUND=0x80802012, SCE_APPMGR_ERROR_NULL_POINTER=0x80802016, SCE_APPMGR_ERROR_INVALID=0x8080201A,
 SCE_APPMGR_ERROR_TOO_LONG_ARGV=0x8080201D, SCE_APPMGR_ERROR_INVALID_SELF_PATH=0x8080201E,
 SCE_APPMGR_ERROR_NOEXEC=0x8080201F, SCE_APPMGR_ERROR_BGM_PORT_BUSY=0x80803000
} SceAppMgrErrorCode;
int sceAppMgrGetRunningAppIdListForShell(SceInt32*,int);
SceUID sceAppMgrGetProcessIdByAppIdForShell(SceInt32);
int sceAppMgrGetNameById(SceUID,char*);
int sceAppMgrGetIdByName(SceUID*,const char*);
int sceAppMgrAppParamGetString(int,int,char*,SceSize);
/* Non-shell per-title query; the info block is 0x80 bytes. */
typedef struct { uint8_t reserved[0x80]; } SceAppMgrAppState;
int sceAppMgrGetAppInfo(const char*,SceAppMgrAppState*);
#endif
''',encoding='utf8')
    selected=Path(header).read_bytes() if header else (S/'wb_app_running_vita.h').read_bytes()
    (t/'wb_app_running_vita.h').write_bytes(selected)
    legacy=["-DWB_FIXTURE_LEGACY_RAW"] if b'int _sceAppMgrGetStatusByName(const char *,void *);' in selected else []
    exe=t/('native.exe' if os.name=='nt' else 'native')
    command=[os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror',*legacy,'-I'+str(t),'-I'+str(S),str(D/'native.c'),str(shell or S/'wb_shell.c'),*(str(S/(x+'.c')) for x in ['wb_cmd','wb_out','wb_str','wb_err']),'-o',str(exe)]
    result=subprocess.run(command,capture_output=True,text=True)
    global LAST_BUILD
    LAST_BUILD=dict(command=command,stdout=result.stdout,stderr=result.stderr,exit_status=result.returncode)
    if result.returncode:
        print(__import__('json').dumps(LAST_BUILD),flush=True)
        result.check_returncode()
    return exe
if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='wb-app-running-') as t:
        subprocess.run([str(build(Path(t)))],check=True)
