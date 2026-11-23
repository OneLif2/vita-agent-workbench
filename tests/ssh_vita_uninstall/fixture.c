#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wb_ver.h"
#include "wb_shell.h"
#include "wb_err.h"
#include "wb_vita_io.h"
#include <psp2/promoterutil.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/threadmgr.h>
static int load_paf(void),unload_paf(void);
#include "wb_ssh_vita_uninstall.inc"
static int probe_control,probe_target,ctl_rc,ctl_val,tgt_rc,tgt_val;
static int fault,deletes,has,registered,cal,busy,loaded,mod_loaded,init_loaded,delay,cmds;
static char output[8192];static size_t used;
static uint8_t sfo[912],boot[181097];
enum {PAF=1,MOD,INIT,REF_POS,REF_MISSING,REF_DB_ERR,WRONG_SFO,WRONG_BOOT,DISK_DENY,STALE_DB,PENDING,DELETE_FAIL,STATE_FAIL,RESULT_CALL_FAIL,RESULT_FAIL,TIMEOUT,STILL,STALE_FILES,POST_DB_IO,EXIT_ERR,MOD_ERR,PAF_ERR,READ_FAIL,SFO_MISSING,BOOT_TYPE};
static void reset(int f){fault=f;has=registered=1;probe_control=probe_target=0;deletes=cmds=busy=delay=0;loaded=mod_loaded=init_loaded=0;cal=0;}
static int load_paf(void){assert(!loaded);if(fault==PAF)return -11;loaded=1;return 0;}
static int unload_paf(void){assert(loaded&&!mod_loaded);loaded=0;return fault==PAF_ERR?-121:0;}
int sceSysmoduleLoadModuleInternal(SceSysmoduleModuleId id){assert(loaded&&id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);if(fault==MOD)return -12;mod_loaded=1;return 0;}
int sceSysmoduleUnloadModuleInternal(SceSysmoduleModuleId id){assert(mod_loaded&&!init_loaded&&id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);mod_loaded=0;return fault==MOD_ERR?-123:0;}
int scePromoterUtilityInit(void){assert(mod_loaded&&!init_loaded);if(fault==INIT)return -13;init_loaded=1;return 0;}
int scePromoterUtilityExit(void){assert(init_loaded);init_loaded=0;return fault==EXIT_ERR?-124:0;}
int scePromoterUtilityCheckExist(const char *id,int *v){
 assert(init_loaded);if(!strcmp(id,WB_TITLE_ID)){if(fault==REF_POS)return -14;*v=cal==4?3:cal==2?0:1;return 0;}
 int exists=registered;
 if(!strcmp(id,WBU_ABS_ID)){if(probe_control){*v=ctl_val;return ctl_rc;}if(fault==REF_MISSING){*v=1;return 0;}if(fault==REF_DB_ERR)return (int)0x80010005u;exists=0;}
 else {assert(!strcmp(id,WBU_ID));if(probe_target){*v=tgt_val;return tgt_rc;}if(fault==STALE_DB)exists=!has;if(fault==POST_DB_IO&&deletes)return -100;}
 if(exists){*v=cal==4?9:cal==2?0:1;return 0;}
 if(cal==4){*v=3;return (int)0x80101005u;}
 if(cal==1){return WBU_NOTFOUND;}if(cal==3){*v=WBU_NOTFOUND;return 0;}*v=cal==2?1:0;return 0;
}
int sceIoGetstat(const char *p,SceIoStat *st){
 if(!strcmp(p,"ux0:/app/" WB_TITLE_ID)){st->st_mode=0x1000;return 0;}
 if(!strcmp(p,"ux0:/app/" WBU_ABS_ID))return WBU_NOTFOUND;
 assert(!strcmp(p,WBU_ROOT)||!strcmp(p,WBU_BOOT)||!strcmp(p,WBU_SFO));
 if(fault==DISK_DENY)return (int)0x8001000du;
 if(!has)return WBU_NOTFOUND;
 if(!strcmp(p,WBU_SFO)&&fault==SFO_MISSING)return WBU_NOTFOUND;
 st->st_mode=!strcmp(p,WBU_ROOT)||(!strcmp(p,WBU_BOOT)&&fault==BOOT_TYPE)?0x1000:0x2000;st->st_size=!strcmp(p,WBU_SFO)?912:181097;return 0;
}
static int read_at(const void *ctx,uint64_t off,void *buf,size_t n){
 if(fault==READ_FAIL)return -1;
 const uint8_t *data=ctx;if(off+n>(data==sfo?sizeof sfo:sizeof boot))return -1;
 memcpy(buf,data+off,n);if(!off&&((data==boot&&fault==WRONG_BOOT)||(data==sfo&&fault==WRONG_SFO)))((uint8_t*)buf)[0]^=1;return 0;
}
int wb_vita_reader_open(const char *p,wb_reader *r,wb_vfile *f){assert(has&&(!strcmp(p,WBU_BOOT)||!strcmp(p,WBU_SFO)));int is_sfo=!strcmp(p,WBU_SFO);r->ctx=is_sfo?sfo:boot;r->size=is_sfo?sizeof sfo:sizeof boot;r->read_at=read_at;f->fd=1;return WB_OK;}
void wb_vita_reader_close(wb_vfile *f){assert(f->fd==1);f->fd=-1;}
int scePromoterUtilityDeletePkg(const char *p){assert(init_loaded&&has&&!strcmp(p,WBU_ID));deletes++;assert(deletes==1);if(fault==DELETE_FAIL)return -15;busy=2;return 0;}
int scePromoterUtilityGetState(int *p){
 if(!deletes){*p=fault==PENDING;return 0;}
 if(fault==STATE_FAIL)return -16;
 if(fault==TIMEOUT){*p=1;return 0;}
 *p=!!busy;if(busy)--busy;return 0;
}
void sceKernelDelayThread(SceUInt us){assert(us==50000);++delay;}
int scePromoterUtilityGetResult(int *p){
 assert(deletes&&!busy);if(fault==RESULT_CALL_FAIL)return -17;
 if(fault==RESULT_FAIL){*p=-18;return 0;}
 if(fault!=STILL){registered=0;if(fault!=STALE_FILES)has=0;}
 *p=0;return 0;
}
static int emit(void *ctx,const char *p,size_t n){(void)ctx;assert(used+n<sizeof output);memcpy(output+used,p,n);used+=n;output[used]=0;return 0;}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){
 (void)ctx;int s=0,*status=&s;cmds++;
 switch(cmd->kind){
 #include "adapter.inc"
 default:assert(0);return -1;
 }
}
static void trial(const char *line,const char *want){
 wb_shell_engine sh;wb_shell_init(&sh);wb_out o={NULL,emit};const wb_shell_ops ops={.core_exec=core};
 used=0;output[0]=0;int rc=wb_shell_run(&sh,line,&o,&ops);
 if(rc!=0||!strstr(output,want)){fprintf(stderr,"line: %s rc=%d output: %s expected: %s\n",line,rc,output,want);abort();}
 assert(!loaded&&!mod_loaded&&!init_loaded);
}
static void file(const char *n,uint8_t*d,size_t size){FILE*f=fopen(n,"rb");assert(f&&fread(d,1,size,f)==size&&fgetc(f)==EOF);fclose(f);}
int main(int argc,char**argv){file("sfo",sfo,sizeof sfo);file("boot",boot,sizeof boot);
 const char *bad[]={"app uninstall","app uninstall INAP00018","app uninstall INAP00019","app uninstall INAP00020","app uninstall VSSH00002",
 "app uninstall vssh00001","app uninstall VSSH00001 extra","app uninstall VSSH00001 --force","app uninstall ux0:/app/VSSH00001","app uninstall ../VSSH00001","app uninstall *","app uninstall VSSH00001;ver","app status INAP00018","app-uninstall VSSH00001","uninstall VSSH00001","app uninstall VSSH00001 | ver"};
 for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){reset(0);trial(bad[i],"ERR ");assert(!cmds&&!deletes);}
 wb_cmd raw;const char *del="app uninstall VSSH00001",*stat="app status VSSH00001";assert(!wb_cmd_parse(del,strlen(del),&raw)||raw.kind!=WB_CMD_TERM_SSH_VITA_UNINSTALL);
 if(argc==2&&!strcmp(argv[1],"--observe-hardware-signature")){
  reset(0);cal=4;
  trial(stat,"");printf("before: %s",output);
  trial(del,"");printf("delete: %s",output);
  trial(stat,"");printf("after: %s",output);
  printf("fixture native delete calls=%d disk=%d registry=%d\n",deletes,has,registered);return 0;
 }
 puts("PASS: PTY rejects 16 other IDs, paths, extra operands, aliases and options; raw exec has no uninstall descriptor; no promoter call.");
 reset(0);trial("help app","app uninstall VSSH00001");assert(!cmds);
 for(int mode=0;mode<5;mode++){reset(0);cal=mode;trial(stat,"app title=VSSH00001 state=installed app_ver=01.42");assert(!deletes);
  trial(del,"OK app-uninstall title=VSSH00001 state=absent");assert(deletes==1&&delay==2&&!has&&!registered);
  trial(stat,"app title=VSSH00001 state=absent");trial(del,"phase=already-absent");assert(deletes==1);}
 puts("PASS: pinned real 01.42 SFO and eboot verified, exactly one VSSH00001 delete, polled operation/result, DB and filesystem independently absent, duplicate delete refused.");
 for(int err=1;err<=BOOT_TYPE;err++){reset(err);trial(del,"ERR app-uninstall-gate ");bool submitted=(err>=DELETE_FAIL&&err<=PAF_ERR);assert(deletes==(int)submitted);assert(strstr(output,submitted?"issued=1":"issued=0"));}
 /* All neighboring LSDB negatives are unknown/fatal here, incl. invalid
  * handle, invalid parameters, constraint or corrupt DB, even with out=3. */
 for(unsigned i=0;i<256;i++){if(i==5)continue;
  reset(0);cal=4;probe_control=1;ctl_rc=(int)(0x80101000u+i);ctl_val=3;
  trial(del,"phase=db-absent-control");assert(!deletes);
  reset(0);cal=4;probe_target=1;tgt_rc=(int)(0x80101000u+i);tgt_val=3;
  trial(del,"phase=title-db");assert(!deletes);
 }
 int values[]={INT_MIN,-1,0,1,2,4,9};for(unsigned i=0;i<sizeof values/sizeof *values;i++){
  reset(0);cal=4;probe_control=1;ctl_rc=(int)0x80101005u;ctl_val=values[i];trial(del,"phase=db-absent-control");assert(!deletes);
  reset(0);cal=4;probe_target=1;tgt_rc=(int)0x80101005u;tgt_val=values[i];trial(del,"phase=title-db");assert(!deletes);
 }
 reset(0);cal=4;probe_target=1;tgt_rc=0;tgt_val=-6;trial(del,"phase=title-db");assert(!deletes);
 reset(0);cal=0;probe_target=1;tgt_rc=0;tgt_val=9;trial(del,"phase=title-db");assert(!deletes);
 reset(0);cal=4;registered=0;trial(del,"phase=title-dir");assert(!deletes);
 reset(0);cal=4;has=0;trial(del,"phase=title-dir");assert(!deletes);
 puts("PASS: hardware-bound 0x80101005/3; controls and target reject 255 same-family LSDB negatives (including 03/04/07/FE/FF) and 7 nonmatching out-words; positive out can differ by title only when negative rc distinguishes absence.");
 puts("PASS: 25 positive/negative controls, real I/O/hash failures, wrong identity, busy/timeout, stale DB/files, indeterminate API and teardown errors; never claim deletion from ACK alone.");
 return 0;
}

