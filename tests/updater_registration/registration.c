/* Real production query/PTY adapters; simulated Vita primitives. No storage
 * writes, network, promote, launch, delete, or layout primitives are linked. */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "wb_err.h"
#include "wb_ver.h"
#include "wb_shell.h"
#include <psp2/io/stat.h>
#include <psp2/promoterutil.h>
#include <psp2/sysmodule.h>
#include "wb_controls_under_test.inc"
enum fault { NONE, PAF, MODULE, INIT, STATE_IO, BUSY, POS_DIR, NEG_DIR, POS_QUERY,
             NEG_QUERY, TARGET_QUERY, BAD_TARGET_WORD, RELEASE_INIT, RELEASE_MOD,
             RELEASE_PAF, CONCURRENT_FAILURE };
static enum fault fail;
static int tracked,registered,mode,asked;
static int load_paf(void){assert(tracked==0);if(fail==PAF)return -101;tracked=1;return 0;}
static int unload_paf(void){assert(tracked==1);tracked=0;return fail==RELEASE_PAF||fail==CONCURRENT_FAILURE?-103:0;}
int sceSysmoduleLoadModuleInternal(SceSysmoduleModuleId id){
    assert(id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL && tracked==1);
    if(fail==MODULE)return -104;
    tracked=2;return 0;}
int sceSysmoduleUnloadModuleInternal(SceSysmoduleModuleId id){
    assert(id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL && tracked==2);tracked=1;
    return fail==RELEASE_MOD?-105:0;}
int scePromoterUtilityInit(void){assert(tracked==2);if(fail==INIT)return -106;tracked=3;return 0;}
int scePromoterUtilityExit(void){assert(tracked==3);tracked=2;return fail==RELEASE_INIT?-107:0;}
int scePromoterUtilityGetState(int *state){assert(tracked==3);if(fail==STATE_IO)return -108;*state=fail==BUSY;return 0;}
int sceIoGetstat(const char *p,SceIoStat *st){
    assert(tracked==3);st->st_mode=0x1000;
    if(!strcmp(p,"ux0:/app/" WB_TITLE_ID))return fail==POS_DIR?WBU_NOTFOUND:0;
    assert(!strcmp(p,"ux0:/app/" WBU_ABS_ID));return fail==NEG_DIR?0:WBU_NOTFOUND;
}
int scePromoterUtilityCheckExist(const char *id,int *out){
    assert(tracked==3); assert(*out==INT_MIN);
    int yes;
    if(!strcmp(id,WB_TITLE_ID)){if(fail==POS_QUERY)return -111;yes=1;}
    else if(!strcmp(id,WBU_ABS_ID)){if(fail==NEG_QUERY){*out=3;return WBU_LSDB_NOT_FOUND+1;}yes=0;}
    else {assert(!strcmp(id,WB_UPDATER_TITLE_ID));asked++;
          if(fail==TARGET_QUERY||fail==CONCURRENT_FAILURE)return -112;
          if(fail==BAD_TARGET_WORD){*out=4;return WBU_LSDB_NOT_FOUND;}
          yes=registered;}
    if(mode==1){*out=yes;return 0;}
    if(mode==2){*out=!yes;return 0;}
    if(mode==3){if(yes){*out=1;return 0;}return WBU_NOTFOUND;}
    if(mode==4){*out=yes?1:WBU_NOTFOUND;return 0;}
    if(yes){*out=!strcmp(id,WB_TITLE_ID)?1:7;return 0;}
    *out=3;return WBU_LSDB_NOT_FOUND;
}
#include "wb_updater_registration.inc"
static unsigned passed;
static void test(int f,int expect_rc,int expect_detail,int expect_asked) {
    int disk=55,detail=55;fail=(enum fault)f;asked=0;
    int rc=wb_vita_updater_registered(&disk,&detail);
    if(rc!=expect_rc || detail!=expect_detail || disk!=(rc==WB_OK?registered:-1) ||
       asked!=expect_asked || tracked!=0) {
        fprintf(stderr,"fault=%d mode=%d requested=%d rc=%d detail=%d observed=%d queries=%d tracked=%d\n",
                f,mode,registered,rc,detail,disk,asked,tracked);assert(0);}
    passed++;
}
/* Only the registration/formatting adapter is being exercised here. Native
 * I/O and identity hashes in wb_updater_probe have their own fixtures. */
static int accesses;
static int wb_updater_probe(int *detail){int found=-1;accesses++;
    int rc=wb_vita_updater_registered(&found,detail);if(!rc)*detail=found;return rc;}
static const char *wb_updater_decision(void){return fail?"helper=refuse phase=registration":
    registered?"helper=reuse epoch=01.74 promote=0":"helper=absent promote=0";}
enum {MODE_B_KEY=1};
static struct {bool authenticated;struct {bool accepted;int mode;} mode;bool session,channel,shell,shell_pty,sftp_ro;} g_ssh;
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;int n=0,*status=&n;
    switch(cmd->kind){
#include "wb_check_cmd_under_test.inc"
    default:assert(0);return -1;
    }
}
static char line[300];static size_t used;
static int emit(void *ctx,const char *p,size_t n){(void)ctx;assert(used+n<sizeof line);memcpy(line+used,p,n);used+=n;line[used]=0;return 0;}
static void command(const char *s,const char *expected,int n){
    wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={.core_exec=core};wb_out o={NULL,emit};
    accesses=0;used=0;line[0]=0;assert(wb_shell_run(&sh,s,&o,&ops)==0);assert(!strcmp(line,expected)&&accesses==n);
}
int main(void){
    for(int m=0;m<5;m++){mode=m;
        for(int active=0;active<=1;active++){registered=active;test(NONE,WB_OK,0,1);}}
    printf("PASS %u calibrated target lookups (5 control signatures, physical tuple 80101005/out=3 included, registered and absent).\n",passed);
    mode=0;registered=1;
    test(PAF,WB_E_IO,-101,0);test(MODULE,WB_E_IO,-104,0);test(INIT,WB_E_IO,-106,0);
    test(STATE_IO,WB_E_IO,-108,0);test(BUSY,WB_E_BUSY,1,0);test(POS_DIR,WB_E_STATE,0,0);test(NEG_DIR,WB_E_STATE,1,0);
    test(POS_QUERY,WB_E_STATE,-111,0);test(NEG_QUERY,WB_E_STATE,WBU_LSDB_NOT_FOUND+1,0);
    test(TARGET_QUERY,WB_E_IO,-112,1);test(BAD_TARGET_WORD,WB_E_IO,WBU_LSDB_NOT_FOUND,1);
    test(RELEASE_INIT,WB_E_IO,-107,1);test(RELEASE_MOD,WB_E_IO,-105,1);test(RELEASE_PAF,WB_E_IO,-103,1);
    test(CONCURRENT_FAILURE,WB_E_IO,-112,1);
    printf("PASS %u registration errors: unknown never becomes absence; reverse cleanup, first error preserved, no promotion linked.\n",passed-10);
    g_ssh.authenticated=g_ssh.mode.accepted=g_ssh.session=g_ssh.channel=g_ssh.shell=g_ssh.shell_pty=true;g_ssh.mode.mode=MODE_B_KEY;fail=NONE;
    command("updater check","OK updater-check title=INAP00019 helper=reuse epoch=01.74 promote=0\n",1);
    registered=0;command("updater check","OK updater-check title=INAP00019 helper=absent promote=0\n",1);
    fail=BUSY;command("updater check","ERR updater-check title=INAP00019 helper=refuse phase=registration rc=busy detail=00000001\n",1);
    fail=NONE;g_ssh.shell_pty=false;command("updater check","ERR paired interactive PTY required\n",0);
    g_ssh.shell_pty=true;g_ssh.sftp_ro=true;command("updater check","ERR paired interactive PTY required\n",0);
    g_ssh.sftp_ro=false;g_ssh.authenticated=false;command("updater check","ERR paired interactive PTY required\n",0);
    g_ssh.authenticated=true;g_ssh.mode.mode=0;command("updater check","ERR paired interactive PTY required\n",0);
    command("updater check INAP00018","ERR usage: updater check\n",0);command("updater repair","ERR usage: updater check\n",0);
    wb_cmd cmd;int raw=wb_cmd_parse("updater check",13,&cmd);assert(!raw||cmd.kind!=WB_CMD_TERM_UPDATER_CHECK);
    puts("PASS paired terminal descriptor (reuse, absence, refusal), PTY gates/arity, no raw exec route. Host fixtures only.");return 0;
}
