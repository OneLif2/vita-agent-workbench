/* Vita I/O test double for the actual compiled wb_updater_install, NOT a Vita/Shell emulator. */
#include "wb_updater.h"
#include "wb_err.h"
#include "wb_head.h"
#include "wb_ver.h"
#include "wb_vita_install.h"
#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/rtc.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char _binary_updater_eboot_bin_start[], _binary_updater_eboot_bin_end[];
extern const unsigned char _historical_eboot_start[], _historical_eboot_end[];
extern const unsigned char _binary_updater_param_sfo_start[], _binary_updater_param_sfo_end[];
#define ABSENT ((int)0x80010002u)
#define IOERR ((int)0x80010005u)
enum { ROOT=0, PBOOT=1, PSFO=2, SBOOT=3, SSFO=4, SHEAD=5, DLOG=6, SROOT=7 };
typedef struct { unsigned char *buf; size_t n,at,cap; int exists; } File;
static File files[6];
static const char *scenario;
static int registry,queries,promotes,rmtree,mkdirs,opens,writes;
static int named(const char *s){return !strcmp(scenario,s);}
static int what(const char *p){
  if(!strncmp(p,"ux0:/",5))p+=5;else if(!strncmp(p,"ux0:",4))p+=4;
  if(!strcmp(p,"app/INAP00019")||!strcmp(p,"app/INAP00019/"))return ROOT;
  if(!strcmp(p,"app/INAP00019/eboot.bin"))return PBOOT;
  if(!strcmp(p,"app/INAP00019/sce_sys/param.sfo"))return PSFO;
  const char *s=strstr(p,"/stage/updater/");
  if(s && !strcmp(s,"/stage/updater/eboot.bin"))return SBOOT;
  if(s && !strcmp(s,"/stage/updater/sce_sys/param.sfo"))return SSFO;
  if(s && !strcmp(s,"/stage/updater/sce_sys/package/head.bin"))return SHEAD;
  if(strstr(p,"/stage/updater") && !s)return SROOT;
  if(strstr(p,"/install.log"))return DLOG;
  fprintf(stderr,"unexpected fixture path: %s\n",p);abort();
}
static void assign(int i,const unsigned char *b,size_t n){
  File *f=&files[i];
  if(f->cap<n){f->buf=realloc(f->buf,n);assert(f->buf);f->cap=n;}
  if(n)memcpy(f->buf,b,n);
  f->n=n;f->at=0;f->exists=1;
}
static void seeded(void){
 files[ROOT].exists=1;registry=1;
 assign(PBOOT,_binary_updater_eboot_bin_start,(size_t)(_binary_updater_eboot_bin_end-_binary_updater_eboot_bin_start));
 assign(PSFO,_binary_updater_param_sfo_start,(size_t)(_binary_updater_param_sfo_end-_binary_updater_param_sfo_start));
}
static void replace_word(int i,const char *from,const char *to){
 assert(strlen(from)==strlen(to));int hits=0;
 for(size_t q=0;q+strlen(from)<=files[i].n;q++)if(!memcmp(files[i].buf+q,from,strlen(from))){memcpy(files[i].buf+q,to,strlen(to));++hits;}
 assert(hits>0);
}
int sceIoGetstat(const char *p,SceIoStat *st){
 int i=what(p);if(i==SROOT){if(named("stage-stat-error"))return IOERR; if(named("stale-stage")){memset(st,0,sizeof *st);st->st_mode=0x1000;return 0;}return ABSENT;}assert(i<=PSFO);if(i==PBOOT&&named("stat-error"))return IOERR;
 if(!files[i].exists)return ABSENT;
 memset(st,0,sizeof *st);st->st_mode=i==ROOT?0x1000:0x2000;
 if(i==PSFO&&named("not-regular"))st->st_mode=0x1000;
 st->st_size=(SceOff)files[i].n;return 0;
}
SceUID sceIoOpen(const char *p,int flags,SceMode mode){
 (void)mode;int i=what(p);if(i==DLOG)return DLOG+11;
 if(i==PBOOT&&named("open-error"))return IOERR;
 if(flags&SCE_O_WRONLY){assert(i>=SBOOT&&i<=SHEAD);++opens;files[i].n=0;files[i].exists=1;}
 else if(!files[i].exists)return ABSENT;
 files[i].at=0;return i+11;
}
int sceIoRead(SceUID fd,void *b,SceSize n){
 int i=fd-11;assert(i==PBOOT||i==PSFO);File *f=&files[i];
 if(named("read-error")&&i==PBOOT)return IOERR;
 if(named("early-eof")&&i==PBOOT&&f->at)return 0;
 if(named("data-beyond-stat")&&i==PBOOT&&f->at==f->n&&n)return 1;
 if(named("too-long-read")&&i==PBOOT)return (int)n+1;
 if(named("short-reads")&&n>13)n=13;
 if((size_t)n>f->n-f->at)n=(SceSize)(f->n-f->at);
 if(n)memcpy(b,f->buf+f->at,n);
 f->at+=n;return (int)n;
}
int sceIoWrite(SceUID fd,const void *b,SceSize n){
 int i=fd-11;if(i==DLOG)return (int)n;
 assert(i>=SBOOT&&i<=SHEAD);++writes;
 if(i==SBOOT&&named("stage-write-error"))return IOERR;
 File *f=&files[i];size_t end=f->at+n;
 if(f->cap<end){f->buf=realloc(f->buf,end);assert(f->buf);f->cap=end;}
 memcpy(f->buf+f->at,b,n);f->at=end;f->n=end;return (int)n;
}
int sceIoClose(SceUID fd){return fd-11==PBOOT&&named("close-error")?IOERR:0;}
int sceIoSyncByFd(SceUID fd,int unused){(void)fd;(void)unused;return 0;}
int sceRtcGetCurrentTick(SceRtcTick *t){t->tick=789;return 0;}
int sceAppMgrLaunchAppByUri(int f,const char *u){(void)f;(void)u;assert(0);return -1;}
int wb_vita_remove_tree(const char *p){assert(!strcmp(p,WB_UPDATER_STAGE));++rmtree;return 0;}
int wb_vita_mkdir_p(const char *p){assert(!strcmp(p,WB_UPDATER_STAGE "/sce_sys/package"));++mkdirs;return 0;}
int wb_vita_updater_registered(int *present,int *detail){++queries;*detail=0;if(queries==2&&(named("racing-match")||named("racing-bad"))){seeded();if(named("racing-bad"))files[PBOOT].buf[110]^=1;}if(named("registry-error")){*detail=IOERR;return WB_E_IO;}*present=registry;return WB_OK;}
int wb_vita_promote_stage(const char *p,bool skip,int *detail){
 assert(!strcmp(p,WB_UPDATER_STAGE)&&skip);++promotes;*detail=0;
 assert(files[SBOOT].n==(size_t)(_binary_updater_eboot_bin_end-_binary_updater_eboot_bin_start));
 assert(files[SSFO].n==(size_t)(_binary_updater_param_sfo_end-_binary_updater_param_sfo_start));
 assert(files[SHEAD].n==WB_HEAD_SIZE);
 if(named("promote-error")){*detail=IOERR;return WB_E_PROMOTE;}
 registry=1;files[ROOT].exists=1;assign(PBOOT,files[SBOOT].buf,files[SBOOT].n);assign(PSFO,files[SSFO].buf,files[SSFO].n);
 if(named("bad-post-promote"))files[PBOOT].buf[100]^=1;
 return WB_OK;
}
static void setup(void){
 if(!named("racing-match")&&!named("racing-bad")&&!named("stage-stat-error")&&!named("stale-stage")&&!named("absent-then-two")&&!named("promote-error")&&!named("stage-write-error")&&!named("bad-post-promote"))seeded();
 if(named("bad-eboot"))files[PBOOT].buf[100]^=1;
 if(named("wrong-title"))replace_word(PSFO,"INAP00019","INAP00089");
 if(named("wrong-version"))replace_word(PSFO,"01.00","09.99");
 if(named("partial-eboot"))files[PBOOT].exists=0;
 if(named("partial-sfo"))files[PSFO].exists=0;
 if(named("orphan-members"))files[ROOT].exists=0;
 if(named("orphan-unregistered")){files[ROOT].exists=0;registry=0;}
 if(named("historic-three"))assign(PBOOT,_historical_eboot_start,(size_t)(_historical_eboot_end-_historical_eboot_start));
 if(named("wrong-size"))--files[PSFO].n;
 if(named("unregistered-files"))registry=0;
 if(named("registered-missing")){files[ROOT].exists=files[PBOOT].exists=files[PSFO].exists=0;}
}
#if HAS_PROBE
#include "wb_shell.h"
enum {MODE_B_KEY=2};
static struct{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh={1,{1,2},1,1,1,1,0};
static int core_status, dispatches;
static int shell_core(void *ctx,const wb_cmd *cmd,wb_out *out) {
 (void)ctx;++dispatches;int *status=&core_status;
 switch(cmd->kind){
 #include "adapter.inc"
 default:abort();}
}
static int sink(void *ctx,const char *b,size_t n){(void)ctx;assert(fwrite(b,1,n,stdout)==n);return 0;}
static int trial(const char *mode){
 if(!strcmp(mode,"unauthenticated"))g_ssh.authenticated=0;
 else if(!strcmp(mode,"unpaired"))g_ssh.mode.accepted=0;
 else if(!strcmp(mode,"no-pty"))g_ssh.shell_pty=0;
 else if(!strcmp(mode,"sftp"))g_ssh.sftp_ro=1;
 const char *line=!strcmp(mode,"bad-args")?"updater check now":"updater check";
 wb_shell_engine sh;wb_shell_init(&sh);wb_out out={NULL,sink};wb_shell_ops ops={.core_exec=shell_core};
 wb_cmd raw;assert(!wb_cmd_parse("updater check",13,&raw) || raw.kind!=WB_CMD_TERM_UPDATER_CHECK);
 assert(wb_shell_run(&sh,line,&out,&ops)==0);
 assert(!promotes&&!rmtree&&!mkdirs&&!opens&&!writes);
 printf("core_status=%d queries=%d dispatches=%d stage_mutations=0 promotes=0\n",core_status,queries,dispatches);return 0;
}
#endif
int main(int argc,char **argv){
 assert(argc==2||argc==3);scenario=argv[1];setup();
#if HAS_PROBE
 if(argc==3)return trial(argv[2]);
#endif
 for(int i=0;i<(named("matching-three")||named("historic-three")||named("absent-then-two")?3:1);++i){
  int d=-1;int rc=wb_updater_install(&d);
  /* Root and member stage mutations are counted, not regular audit log appends. */
  printf("pass=%d rc=%d detail=%d promotes=%d stage_removes=%d stage_mkdirs=%d stage_write_opens=%d stage_writes=%d queries=%d\n",
   i+1,rc,d,promotes,rmtree,mkdirs,opens,writes,queries);
 }
 for(size_t i=0;i<sizeof files/sizeof files[0];++i)free(files[i].buf);
 return 0;
}
