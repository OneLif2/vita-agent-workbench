#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_err.h"
#include "wb_shell.h"
#include "wb_vita_io.h"
#include "wb_ver.h"
#include <psp2/promoterutil.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/threadmgr.h>
#include "database.inc"

#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
#define TITLE "WBLC00079"
#define ALT "ABCD00001"

enum{MODE_B_KEY=2};
static struct conn{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static struct{char run_hex[17];}a={"ABCDEF123456789A"};
static char target[10],output[4096];static size_t used;
static uint8_t sfo[4096],boot[1048576];static size_t sn,bn;
static int disk,db,system_shadow,broken_boot,delete_calls,reads,loads,initialized;
static void load_one(const char *path,uint8_t *buf,size_t max,size_t *len){
 FILE *f=fopen(path,"rb");CK(f);*len=fread(buf,1,max,f);CK(*len&&*len<max&&fgetc(f)==EOF);fclose(f);}
static int load_paf(void){++loads;return 0;}
static int unload_paf(void){return 0;}
int sceSysmoduleLoadModuleInternal(SceSysmoduleModuleId id){CK(id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);return 0;}
int sceSysmoduleUnloadModuleInternal(SceSysmoduleModuleId id){CK(id==SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);return 0;}
int scePromoterUtilityInit(void){CK(!initialized);initialized=1;return 0;}
int scePromoterUtilityExit(void){CK(initialized);initialized=0;return 0;}
int scePromoterUtilityCheckExist(const char *id,int *v){
 CK(initialized);if(!strcmp(id,WB_TITLE_ID)){*v=7;return 0;}
 if(!strcmp(id,WBU_ABS_ID)){*v=3;return WBU_LSDB_NOT_FOUND;}
 CK(!strcmp(id,target));*v=db?9:3;return db?0:WBU_LSDB_NOT_FOUND;
}
int scePromoterUtilityDeletePkg(const char *title){(void)title;++delete_calls;CK(0);return -1;}
int scePromoterUtilityGetState(int *v){(void)v;CK(0);return -1;}
int scePromoterUtilityGetResult(int *v){(void)v;CK(0);return -1;}
void sceKernelDelayThread(SceUInt us){(void)us;CK(0);}
uint64_t sceKernelGetProcessTimeWide(void){return 12345000u;}
static int kind(const char *p){
 const char *prefix="ux0:/app/";CK(!strncmp(p,prefix,strlen(prefix)));p+=strlen(prefix);
 CK(!strncmp(p,target,9));p+=9;
 if(!*p)return 1;
 if(!strcmp(p,"/sce_sys/param.sfo"))return 2;
 CK(!strcmp(p,"/eboot.bin"));return 3;
}
int sceIoGetstat(const char *p,SceIoStat *s){
 if(!strncmp(p,"vs0:/app/",9)){CK(!strcmp(p+9,target));s->st_mode=0x1000;return system_shadow?0:WBU_NOTFOUND;}
 if(!strcmp(p,"ux0:/app/" WB_TITLE_ID)){s->st_mode=0x1000;return 0;}
 if(!strcmp(p,"ux0:/app/" WBU_ABS_ID))return WBU_NOTFOUND;
 int k=kind(p);
 if(!disk || (k==3&&broken_boot))return WBU_NOTFOUND;
 s->st_mode=k==1?0x1000:0x2000;s->st_size=k==2?sn:k==3?bn:0;return 0;
}
static int read_at(const void *ctx,uint64_t off,void *buf,size_t n){
 const uint8_t *raw=ctx;CK(raw==sfo||raw==boot);size_t max=raw==sfo?sn:bn;CK(off<=max&&n<=max-(size_t)off);
 memcpy(buf,raw+(size_t)off,n);return WB_OK;}
int wb_vita_reader_open(const char *p,wb_reader *r,wb_vfile *f){
 int k=kind(p);CK(k==2||k==3);++reads;
 r->ctx=k==2?sfo:boot;r->size=k==2?sn:bn;r->read_at=read_at;f->fd=k;return WB_OK;
}
void wb_vita_reader_close(wb_vfile *f){CK(f->fd==2||f->fd==3);f->fd=-1;}
#include "wb_managed_app.inc"
static int sink(void *ctx,const char *s,size_t n){(void)ctx;
 CK(used+n<sizeof output);memcpy(output+used,s,n);used+=n;output[used]=0;return 0;}
static int exec(void *ctx,const wb_cmd *cmd,wb_out *out){
 (void)ctx;int st=0,*status=&st;
 switch(cmd->kind){
 #include "dispatch.inc"
 default:CK(0);return -1;}}
static void run(const char *cmd){
 wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={.core_exec=exec};wb_out out={NULL,sink};
 used=0;output[0]=0;CK(!wb_shell_run(&sh,cmd,&out,&ops)&&!delete_calls&&!initialized);
}
static void ready(const char *tag){
 char file[40];snprintf(file,sizeof file,"%s-sfo",tag);load_one(file,sfo,sizeof sfo,&sn);
 snprintf(file,sizeof file,"%s-boot",tag);load_one(file,boot,sizeof boot,&bn);
 strcpy(target,TITLE);disk=db=1;system_shadow=broken_boot=delete_calls=reads=loads=0;
 g_ssh=(struct conn){1,{1,MODE_B_KEY},1,1,1,1,0};wb_vita_forget_remove_plan();
}
static void edit(const char *from,const char *to){
 size_t n=strlen(from)+1;CK(strlen(to)<n);
 for(size_t i=0;i+n<=sn;i++)if(!memcmp(sfo+i,from,n)){memset(sfo+i,0,n);memcpy(sfo+i,to,strlen(to));return;}
 CK(0);
}
static void expect(const char *cmd,const char *want){run(cmd);if(!strstr(output,want)){
 fprintf(stderr,"wanted '%s' in '%s' for '%s'\n",want,output,cmd);exit(3);}}
int main(int argc,char **argv){
 const char *stat="app status " TITLE;
 ready("new");
 if(argc==2){run(argv[1]);fputs(output,stdout);return 0;}
 ready("old");expect(stat,"app title=WBLC00079 state=installed app_ver=01.00\n");CK(reads==2);
 ready("new");expect(stat,"app title=WBLC00079 state=installed app_ver=01.01\n");CK(reads==2);
 puts("PASS original and candidate foreground SFOs: exact read-only 01.00/01.01 status");
 for(int i=0;i<8;i++){ready("new");int *gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
  *gate[i]=(i==7);expect(stat,"ERR paired interactive PTY required");CK(!loads&&!reads);}
 ready("new");edit("gdc","gdd");expect(stat,"phase=sfo-identity");CK(reads==1);
 ready("new");edit("01.01","01.02");expect(stat,"app title=WBLC00079 state=installed app_ver=01.02\n");CK(reads==2);
 puts("PASS narrow read-only 01.02 version fixture; launch/delete permissions unchanged");
 ready("new");edit("01.01","01.03");expect(stat,"phase=sfo-identity");CK(reads==1);
 ready("new");strcpy(target,ALT);edit(TITLE,ALT);expect("app status " ALT,"phase=sfo-identity");CK(reads==1);
 ready("new");edit(TITLE,ALT);expect(stat,"phase=sfo-identity");CK(reads==1);
 puts("PASS no-PTY, gdd, new unknown version, and another title are rejected");
 ready("new");expect("app uninstall-plan " TITLE,"phase=sfo-identity");CK(reads==1&&!wb_remove_plan.token[0]);
 ready("new");expect("app uninstall " TITLE " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","phase=token");CK(!loads);
 ready("plain");strcpy(target,"INAP00020");expect("app status INAP00020","app title=INAP00020 state=installed app_ver=01.01");
 puts("PASS gdc has no uninstall token/submit; gd path preserved");
 ready("new");disk=db=0;expect(stat,"state=absent");CK(!reads);
 ready("new");db=0;expect(stat,"phase=title-dir");CK(!reads);
 ready("new");broken_boot=1;expect(stat,"phase=title-eboot");CK(!reads);
 ready("new");system_shadow=1;expect(stat,"phase=system-path");CK(!reads);
 puts("PASS independent DB/files, required eboot, and protected mount checks preserved");
 return 0;
}
