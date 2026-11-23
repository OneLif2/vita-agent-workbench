/* Isolated in-memory IO only. Real S4 issue/consume + C2 append/dump. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <psp2/apputil.h>
#include <psp2/io/stat.h>
#include <psp2/rtc.h>
#include <psp2/kernel/rng.h>
#include "wb_err.h"
#include "wb_ver.h"
#include "wb_vita_io.h"
#include "wb_timeline.h"
#define WB_JOB_PATH WB_ROOT "/job.txt"
static void hex(char *out,const uint8_t *b,size_t n) {for(size_t i=0;i<n;i++)sprintf(out+2*i,"%02X",b[i]);}
#include "wb_autoarm_vita.h"
#define NODATA ((int)UINT32_C(0x80010002))
#define CUR WB_ROOT "/timeline.txt"
#define PREV WB_ROOT "/timeline-prev.txt"
#define TMP WB_ROOT "/timeline-new.txt"
static const char *const names[]={WB_ARM_PATH,WB_JOB_PATH,WB_ARM_MARKER,CUR,PREV,TMP};
enum{N=6};typedef struct{char bytes[8820];size_t n;bool present;} file;
static file files[N];static uint64_t now=10000000;static int rnd=8,fail_save,fail_remove,fail_write,fail_sync,fail_close,fail_publish,syncs;
static int idx(const char *s){for(int k=0;k<N;k++)if(!strcmp(s,names[k]))return k;assert(!"unexpected path");return -1;}
static void assign(const char *s,const void *data,size_t n){file*f=&files[idx(s)];assert(n<sizeof f->bytes);memcpy(f->bytes,data,n);f->bytes[n]=0;f->n=n;f->present=true;}
int sceRtcGetCurrentTick(SceRtcTick *x){x->tick=now;return 0;}
int sceKernelGetRandomNumber(void *d,SceSize n){memset(d,rnd++,n);return 0;}
uint64_t sceKernelGetProcessTimeWide(void){return now;}
int sceAppUtilSaveDataDataSave(SceAppUtilSaveDataFileSlot*s,SceAppUtilSaveDataFile*f,unsigned n,SceAppUtilSaveDataMountPoint*m,SceSize*r){
    assert(!s&&!m&&r&&n==1&&!strcmp(f->filePath,WB_ARM_NAME));if(fail_save)return -1;assign(WB_ARM_PATH,f->buf,f->bufSize);return 0;}
int wb_vita_read_small(const char *p,void *out,size_t cap,size_t *n){file *f=&files[idx(p)];if(!f->present)return WB_E_IO;*n=f->n<cap?f->n:cap;memcpy(out,f->bytes,*n);return WB_OK;}
int wb_vita_write_file(const char *p,const void *b,size_t n,bool append){assert(!append);assign(p,b,n);return WB_OK;}
int sceIoRemove(const char *p){file*f=&files[idx(p)];if(fail_remove&&idx(p)==2)return -1;if(!f->present)return NODATA;f->present=false;return 0;}
int sceIoRename(const char *src,const char *dst){file *a=&files[idx(src)],*b=&files[idx(dst)];
    if(fail_publish&&idx(src)==5)return -1;
    if(!a->present||b->present)return -1;
    *b=*a;a->present=false;return 0;}
int sceIoGetstat(const char *p,SceIoStat *s){file*f=&files[idx(p)];if(!f->present)return NODATA;memset(s,0,sizeof *s);s->st_mode=0x2000;s->st_size=f->n;return 0;}
int sceIoOpen(const char *p,int flags,SceMode mode){assert(!strcmp(p,TMP));assert(flags&&mode);assign(TMP,"",0);return idx(p);}
int sceIoWrite(int fd,const void *b,SceSize n){assert(fd==idx(TMP));int k=fail_write?(int)n-1:(int)n;assign(TMP,b,(size_t)k);return k;}
int sceIoClose(int fd){assert(fd==idx(TMP));return fail_close?-1:0;}
int sceIoSyncByFd(int fd,int flags){assert(fd==idx(TMP)&&!flags);syncs++;return fail_sync?-1:0;}
static int at(const void *ctx,uint64_t off,void *dest,size_t n){file*f=(file*)ctx;assert(off+n<=f->n);memcpy(dest,f->bytes+off,n);return 0;}
int wb_vita_reader_open(const char *p,wb_reader *rd,wb_vfile*f){file *data=&files[idx(p)];if(!data->present)return -1;rd->ctx=data;rd->read_at=at;rd->size=data->n;f->fd=idx(p);return 0;}
void wb_vita_reader_close(wb_vfile*f){f->fd=-1;}
static char reply[8000];static int output(void*ctx,const char *p,size_t n){(void)ctx;size_t l=strlen(reply);assert(n+l<sizeof reply);memcpy(reply+l,p,n);reply[l+n]=0;return 0;}
static void return_from_testapp(void){wb_arm_intent i;char j[160],m[144];size_t n;assert(!wb_vita_read_small(WB_ARM_PATH,&i,sizeof i,&n));assert(n==sizeof i&&wb_arm_text(&i,j,m));assign(WB_ARM_MARKER,m,strlen(m));}
static void issue(void){assert(!wb_arm_issue("job-1","fs-smoke"));return_from_testapp();}
int main(void){
    char accepted[64]={0};assert(wb_arm_selftest()==8 && wb_timeline_selftest()==4);
    assign(WB_ARM_MARKER,"autoarm\n",8);assert(!wb_arm_consume(accepted));
    issue();file old=files[2];assert(wb_arm_consume(accepted)&&!strcmp(accepted,"job-1"));
    files[2]=old;assert(!wb_arm_consume(accepted)); /* previously spent */
    issue();files[2]=old;assert(!wb_arm_consume(accepted)); /* copied marker; even when job ID reused */
    issue();files[1].bytes[4]='x';assert(!wb_arm_consume(accepted));
    issue();files[2].bytes[4]='x';assert(!wb_arm_consume(accepted));
    issue();now+=120000000;assert(!wb_arm_consume(accepted));
    issue();now--;assert(!wb_arm_consume(accepted));now++;
    issue();fail_remove=1;assert(!wb_arm_consume(accepted));fail_remove=0;assert(!wb_arm_consume(accepted));
    issue();fail_save=1;assert(!wb_arm_consume(accepted));fail_save=0;assert(!wb_arm_consume(accepted));
    issue();assert(wb_arm_cancel()==0);assert(!wb_arm_consume(accepted));
    puts("S4 PASS: real issue/consume + isolated I/O: fresh job, spent replay, reused job ID, mismatched job/marker, legacy, expired/future, consume failures, launch cancellation.");
    wb_out o={NULL,output};int before=syncs;assert(!wb_timeline_note("boot","01.32","A"));assert(syncs==before+1);file prior=files[idx(CUR)];
    for(int e=0;e<4;e++){
        fail_write=e==0;fail_sync=e==1;fail_close=e==2;fail_publish=e==3;
        assert(wb_timeline_note("updater","01.32","X")==WB_E_IO);assert(!memcmp(&files[idx(CUR)],&prior,sizeof prior));
        reply[0]=0;assert(wb_timeline_dump(&o,40)==WB_E_IO);assert(strstr(reply,"stage=boot")&&!strstr(reply,"stage=updater")&&strstr(reply,"ERR timeline-not-saved"));
        fail_write=fail_sync=fail_close=fail_publish=0;
    }
    assert(!wb_timeline_note("verified","01.32","B"));reply[0]=0;assert(!wb_timeline_dump(&o,1));assert(strstr(reply,"stage=verified")&&!strstr(reply,"stage=boot"));assert(files[idx(PREV)].present);
    files[idx(CUR)].present=false;reply[0]=0;assert(!wb_timeline_dump(&o,40));assert(strstr(reply,"stage=boot"));
    puts("C2 PASS: real timeline note/dump + isolated I/O: write -> sync -> close -> publish, faults on short write/sync/close/rename preserve prior bytes, fallback retained, last-line read.");
    return 0;
}

