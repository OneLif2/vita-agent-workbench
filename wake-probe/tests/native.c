#include "fake.h"
#include "life.h"
#include "probe_io.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL %s line %d\n",mode,__LINE__);exit(90);}}while(0)
static const char*mode;
typedef struct{char path[128];unsigned n;unsigned char b[512];int exists;} File;
static File files[16];static struct{File*f;unsigned pos;int flags;}fds[16];
static uint64_t now=100000000,epoch=63000000000000000ULL;
static unsigned bg_calls,return_calls,exit_calls,sequence,return_order,exit_order,job_opens,publishes,trace_writes;
static int worker_phase;static wp_result final_receipt;static unsigned waits;
static int is(const char*s){return !strcmp(mode,s);}
static File*file(const char*p){for(unsigned i=0;i<16;i++)if(!strcmp(files[i].path,p))return files+i;for(unsigned i=0;i<16;i++)if(!files[i].path[0]){CK(strlen(p)<sizeof files[i].path);strcpy(files[i].path,p);return files+i;}CK(0);return NULL;}
static void put(const char*p,const void*b,unsigned n){File*f=file(p);CK(n<=sizeof f->b);memcpy(f->b,b,n);f->n=n;f->exists=1;}
int sceAppUtilInit(SceAppUtilInitParam*p,SceAppUtilBootParam*b){(void)p;(void)b;return is("init")?-72:0;}
int sceAppUtilSaveDataDataSave(void*a,SceAppUtilSaveDataFile*f,int n,void*d,SceSize*req){(void)a;(void)d;CK(n==1&&req&&f->mode==0);if(is("claimsave")&&!strcmp(f->filePath,WP_CLAIM_NAME))return -73;if(!strcmp(f->filePath,"wake-probe-ticks.bin")){trace_writes++;if(worker_phase&&is("workertracefail")&&trace_writes==3)return -83;}char p[128];snprintf(p,sizeof p,"savedata0:/%s",f->filePath);put(p,f->buf,f->bufSize);return 0;}
int sceIoOpen(const char*p,int flags,int permission){(void)permission;File*f=file(p);if(!strcmp(p,WP_JOB_PATH)){job_opens++;if(is("mutate")&&job_opens==2)f->b[16]='B';}
 if(flags&SCE_O_WRONLY){if(!strcmp(p,WP_RESULT_PATH)){publishes++;if(is("publicfail")||(worker_phase&&is("workerpublic")&&publishes>=4))return -74;}f->exists=1;if(flags&SCE_O_TRUNC)f->n=0;}else if(!f->exists)return (int)0x80010002u;
 for(int i=1;i<16;i++){if(!fds[i].f){fds[i].f=f;fds[i].pos=0;fds[i].flags=flags;return i;}}
 return -91;}
int sceIoRead(int fd,void*out,unsigned n){CK(fd>0&&fd<16&&fds[fd].f&&fds[fd].flags==SCE_O_RDONLY);File*f=fds[fd].f;unsigned left=f->n-fds[fd].pos;if(n>left)n=left;if(n>13)n=13;memcpy(out,f->b+fds[fd].pos,n);fds[fd].pos+=n;return (int)n;}
int sceIoWrite(int fd,const void*in,unsigned n){CK(fd>0&&fd<16&&fds[fd].f&&(fds[fd].flags&SCE_O_WRONLY));File*f=fds[fd].f;if(n>17)n=17;CK(fds[fd].pos+n<=sizeof f->b);memcpy(f->b+fds[fd].pos,in,n);fds[fd].pos+=n;if(f->n<fds[fd].pos)f->n=fds[fd].pos;return (int)n;}
int sceIoClose(int fd){CK(fd>0&&fd<16&&fds[fd].f);memset(fds+fd,0,sizeof fds[fd]);return 0;}
int sceIoSyncByFd(int fd,int flags){CK(fd>0&&fd<16&&fds[fd].f&&!flags);return is("syncfail")?-75:0;}
int sceIoRemove(const char*p){CK(!strcmp(p,WP_JOB_PATH));if(is("consume"))return -76;File*f=file(p);if(!f->exists)return (int)0x80010002u;f->exists=0;return 0;}
int sceRtcGetCurrentTick(SceRtcTick*t){if(is("clockrc"))return -71;t->tick=is("underflow")?now:now+epoch;return 0;}
uint64_t sceKernelGetSystemTimeWide(void){return now;}
int sceKernelDelayThread(unsigned usec){
 if(usec==100000){now+=usec;waits++;if((is("receiptwait")||is("receipttorn"))&&waits==2)put("savedata0:/" WP_MAIN_NAME,&final_receipt,sizeof final_receipt);return 0;}
 CK(usec==5000000);now+=is("workergap")?20000000:usec;
 if(is("workerepoch"))epoch+=10000000;
 if(is("workerjobchange")){File*f=file("savedata0:/" WP_CLAIM_NAME);f->b[16]^=1;}
 if(is("workerarm")||is("workerrevoke")){File*f=file("savedata0:/wake-probe-arm.bin");lc_arm a;memcpy(&a,f->b,sizeof a);if(is("workerarm"))a.start++;else a.enabled=0;put(f->path,&a,sizeof a);}
 return 0;}
int sceSysmoduleLoadModule(int id){CK(id==24);if(is("slowmodule"))now+=30000000;return is("modfail")?-77:0;}
int sceBgAppUtilStartBgApp(int arg){CK(arg==1);bg_calls++;return is("bgfail")?-78:0;}
int sceAppMgrLaunchAppByUri(int flags,const char*uri){CK(flags==0x20000&&!strcmp(uri,"psgm:play?titleid=INAP00018"));return_calls++;return_order=++sequence;return is("returnfail")?-79:0;}
int sceKernelExitProcess(int status){CK(status==0||status==2);exit_calls++;exit_order=++sequence;return 0;}
extern int probe_main(void);extern int worker_main(void);
int main(int argc,char**argv){CK(argc==2);mode=argv[1];wp_job job={0};memcpy(job.magic,WP_JOB_MAGIC,8);job.version=1;job.bytes=sizeof job;memset(job.nonce,'A',32);memset(job.source_run,'C',16);strcpy(job.job_id,"host_job_01");job.issued_us=now-1000000;job.deadline_us=now+20000000;job.boot_epoch_us=epoch;
 if(is("badnonce"))memset(job.nonce,'0',32);
 if(is("badid"))strcpy(job.job_id,"../bad");
 if(is("expired"))job.deadline_us=now;
 if(is("future")){job.issued_us=now+1;job.deadline_us=now+10;}if(is("overttl"))job.deadline_us=job.issued_us+WP_JOB_TTL_US+1;
 if(is("boot"))job.boot_epoch_us+=3000000;
 put(WP_JOB_PATH,&job,sizeof job);if(is("missing"))file(WP_JOB_PATH)->exists=0;if(is("short"))file(WP_JOB_PATH)->n--;if(is("trailing"))file(WP_JOB_PATH)->n++;
 lc_arm prior={LC_MAGIC,1,now-1000};if(is("active"))put("savedata0:/wake-probe-arm.bin",&prior,sizeof prior);if(is("replay"))put("savedata0:/" WP_CLAIM_NAME,&job,sizeof job);
 int rc=probe_main();int early=is("missing")||is("short")||is("trailing")||is("badnonce")||is("badid")||is("expired")||is("future")||is("overttl")||is("boot")||is("clockrc")||is("underflow")||is("init")||is("active")||is("replay");
 if(early){CK(rc!=0&&!bg_calls&&!return_calls&&!exit_calls);if(is("active")){lc_arm a;CK(!lc_load_arm(&a)&&!memcmp(&a,&prior,sizeof a));}printf("case=%s main=%d bg=0 returned=0 no-arm\n",mode,rc);return 0;}
 CK(return_calls==1&&exit_calls==1&&return_order<exit_order);
 int fail=is("claimsave")||is("publicfail")||is("syncfail")||is("consume")||is("modfail")||is("bgfail")||is("returnfail")||is("mutate")||is("slowmodule");
 if(fail){CK(rc==2);if(!is("bgfail")&&!is("returnfail"))CK(!bg_calls);wp_result r;if(!wp_load_main(&r)){CK(r.first_error_step&&r.first_error_rc);if(is("bgfail"))CK(r.first_error_step==WP_E_BG_START&&r.first_error_rc==-78);if(is("returnfail"))CK(r.first_error_step==WP_E_RETURN&&r.first_error_rc==-79);}printf("case=%s main=%d bg=%u returned=%u first-error-preserved\n",mode,rc,bg_calls,return_calls);return 0;}
 CK(rc==0&&bg_calls==1&&!file(WP_JOB_PATH)->exists);wp_job claimed;CK(!wp_load_claim(&claimed)&&!memcmp(&claimed,&job,sizeof job));wp_result r;CK(!wp_load_main(&r)&&wp_result_matches(&r,&job)&&r.bg_rc==0&&r.return_rc==0&&r.main_exit_intent==1);CK(r.tick_count==0);
 if(is("receiptwait")||is("receipttorn")||is("receipttimeout")){
  final_receipt=r;wp_result incomplete=r;incomplete.main_exit_intent=0;incomplete.return_rc=WP_RC_UNKNOWN;
  put("savedata0:/" WP_MAIN_NAME,&incomplete,sizeof incomplete);
  if(is("receipttorn"))file("savedata0:/" WP_MAIN_NAME)->n=120;
 }
 worker_phase=1;int wr=worker_main();CK(!wp_read_exact(WP_RESULT_PATH,&r,sizeof r));CK(wp_result_matches(&r,&job));
 if(is("workerjobchange")||is("workerepoch")||is("workerarm")||is("workertracefail")||is("workerpublic")||is("workergap")||is("receipttimeout")){CK(wr!=0||is("workerpublic"));if(!is("workerpublic"))CK(r.first_error_step&&r.first_error_rc);printf("case=%s main=0 bg=1 worker=%d ticks=%u rejected-after-first-tick\n",mode,wr,r.tick_count);return 0;}
 CK(wr==0&&r.worker_exit_rc==0);if(is("workerrevoke"))CK(r.tick_count==1);else CK(r.tick_count==24&&r.last_tick_us-r.first_tick_us==115000000&&r.max_gap_us==5000000);if(is("receiptwait")||is("receipttorn"))CK(waits==2);CK(bg_calls==1);printf("case=%s main=0 bg=1 returned=1 worker=0 ticks=%u gap_us=%llu diagnostic-only\n",mode,r.tick_count,(unsigned long long)r.max_gap_us);return 0;
}
