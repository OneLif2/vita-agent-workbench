/* Test-only OS adapter. Executed with cwd in a fresh, disposable temp directory. */
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _WIN32
#include <io.h>
#include <direct.h>
#define MK(p,m) _mkdir(p)
#define FSYNC _commit
#define BIN O_BINARY
#else
#define MK(p,m) mkdir(p,m)
#define FSYNC fsync
#define BIN 0
#endif
#include "wbq_fixture.h"
#include "wb_install.h"
#include "wb_ext_path_policy.h"
#include "wb_vita_io.h"
static const char *native(const char *p){
 static char a[1024];if(strlen(p)>=sizeof a || strstr(p,"..") || p[0]=='/')exit(90);
 strcpy(a,p);for(size_t i=0;a[i];i++)if(a[i]==':')a[i]='_';return a;
}
static DIR *dirs[12];static char paths[12][WQPATH];
int sceIoMkdir(const char *p,SceMode m){(void)m;return MK(native(p),0770);}
int sceIoRmdir(const char *p){return rmdir(native(p));}
int sceIoRemove(const char *p){return unlink(native(p));}
int sceIoGetstat(const char *p,SceIoStat *s){struct stat st;
 if(stat(native(p),&st)<0)return -1;
 memset(s,0,sizeof *s);s->st_mode=S_ISDIR(st.st_mode)?0x1000:0x2000;s->st_size=st.st_size;return 0;}
int sceIoDopen(const char *p){for(int i=0;i<12;i++)if(!dirs[i]){dirs[i]=opendir(native(p));if(!dirs[i])return -1;strcpy(paths[i],p);return i;}return -1;}
int sceIoDread(int i,SceIoDirent *e){struct dirent *d=readdir(dirs[i]);if(!d)return 0;
 if(strlen(d->d_name)>=sizeof e->d_name)return -1;
 memcpy(e->d_name,d->d_name,strlen(d->d_name)+1);
 if(!strcmp(e->d_name,".") || !strcmp(e->d_name,".."))return 1;
 char p[512];snprintf(p,sizeof p,"%s/%s",paths[i],e->d_name);return sceIoGetstat(p,&e->d_stat)<0?-1:1;}
int sceIoDclose(int i){int rc=closedir(dirs[i]);dirs[i]=NULL;return rc;}
int sceIoOpen(const char *p,int f,SceMode m){int flags=(f&SCE_O_WRONLY)?O_WRONLY:O_RDONLY;
 if(f&SCE_O_CREAT)flags|=O_CREAT;if(f&SCE_O_TRUNC)flags|=O_TRUNC;if(f&SCE_O_APPEND)flags|=O_APPEND;
 (void)m;return open(native(p),flags|BIN,0666);}
int sceIoRead(int fd,void *p,SceSize n){return read(fd,p,n);}
int sceIoWrite(int fd,const void *p,SceSize n){return write(fd,p,n);}
int sceIoClose(int fd){return close(fd);}
int sceIoSyncByFd(int fd,int flag){(void)flag;return FSYNC(fd);}
SceOff sceIoLseek(int fd,SceOff n,int mode){return lseek(fd,n,mode);}
static wb_vfile vf;static wb_vwriter vw;static int resets,seals,tweak,calls;
static int h_open(void *ctx,const char *p,wb_reader *rd){(void)ctx;return wb_vita_reader_open(p,rd,&vf);}
static void h_close(void *ctx){(void)ctx;wb_vita_reader_close(&vf);}
static const wb_writer *h_writer(void *c){(void)c;return wb_vita_writer_ops(&vw);}
static int h_reset(void *ctx){(void)ctx;resets++;wq_cleanup(WB_STAGE_DIR);return wb_vita_writer_init(&vw,WB_STAGE_DIR);}
static int h_head(void *ctx,const uint8_t *h,size_t n){(void)ctx;
 char p[WQPATH];if(wq_dirs(WB_STAGE_DIR)||wq_path(p,WB_STAGE_DIR,wbq_names[2]))return WB_E_IO;
 return wq_save(p,h,n);}
static int h_seal(void *ctx,const char *receipt,const char *running){(void)ctx;
 if(tweak)wq_save(WB_STAGE_DIR "/sce_sys/package/head.bin","fixture changed after extraction",32);
 int rc=wq_check_tree(WB_STAGE_DIR,NULL,receipt,running);
 if(!rc)rc=wq_save(WBQ_SEAL,receipt,strlen(receipt));
 if(!rc)rc=wq_save(WB_PENDING_PATH,receipt,strlen(receipt));
 if(!rc)seals++;
 return rc;}
static int h_handoff(const char *path,void *ctx){(void)ctx;if(strcmp(path,WBQ_FINAL))return -1;calls++;return 0;}
int main(int argc,char **argv){if(argc!=2)return 2;char report[1024];
 char *moves1[]={(char*)WB_ROOT "/candidate",(char*)WBQ_SEAL};
 char *moves2[]={(char*)"ux0:data/inap00019",(char*)WB_ROOT "/other"};
 if(wb_ext_operands_ok("mv",2,moves1) || wb_ext_operands_ok("mv",2,moves2) ||
    wb_ext_path_ok(WBQ_FINAL,true) || wb_ext_path_ok(WBQ_TEST,true) ||
    wb_ext_path_ok(WB_ROOT,true) || !wb_ext_path_ok(WB_INCOMING "/own.vpk",true))return 1;
 puts("private seal & handoff paths: public API writes denied PASS");
 int rc=wq_fx_run("0000000000000001",report,sizeof report);printf("%s",report);if(rc)return 1;
 wb_inst_backend b={.open_vpk=h_open,.close_vpk=h_close,.stage_reset=h_reset,.writer=h_writer,.save_head=h_head,.seal_stage=h_seal};
 wb_inst_request q={.vpk="core.vpk",.sha256=argv[1],.running_ver="01.30"};wb_inst_result r;
 const char *const modes[]={"no-expected-sha","wrong-sha","same-version","immediate-force","original","injected-stage-write"};
 const int wanted[]={WB_E_SHA,WB_E_SHA,WB_E_VERSION,WB_E_STATE,WB_OK,WB_E_SHA};
 for(int k=0;k<6;k++){
  q.sha256=k==0?NULL:k==1?"0000000000000000000000000000000000000000000000000000000000000000":argv[1];
  q.running_ver=k==2?"01.31":"01.30";q.promote=k==3;tweak=k==5;
  int rs=resets,ss=seals;rc=wb_install_run(&q,&b,NULL,&r);
  int ok=rc==wanted[k] && resets-rs==(k>=4?1:0) && seals-ss==(k==4?1:0);
  if(k==4 && ok)ok=!wq_final(WB_PENDING_PATH,WBQ_SEAL,WB_STAGE_DIR,WBQ_FINAL,"01.30",h_handoff,NULL) && calls==1;
  printf("install-%s rc=%d expected=%d stage=%d seal=%d %s\n",modes[k],rc,wanted[k],resets-rs,seals-ss,ok?"PASS":"FAIL");
  if(!ok)return 1;
 }
 return 0;
}
