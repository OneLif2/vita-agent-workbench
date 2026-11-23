#include "wb_timeline.h"
#include "wb_err.h"
#include "wb_ver.h"
#include "wb_vita_io.h"
#include <psp2/io/fcntl.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/io/stat.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define TL_CUR WB_ROOT "/timeline.txt"
#define TL_OLD WB_ROOT "/timeline-prev.txt"
#define TL_NEW WB_ROOT "/timeline-new.txt"
enum { TL_MAX=6000, TL_LINE=128 };
static int last_error;
static char history[TL_MAX+TL_LINE]; /* private single-threaded core, NOT on SSH thread stack */
static int absent(int rc) { return (uint32_t)rc==UINT32_C(0x80010002); }
static int present(const char *path) {
    SceIoStat st={0};int rc=sceIoGetstat(path,&st);
    return rc>=0 ? (SCE_S_ISREG(st.st_mode)?1:-1) : absent(rc)?0:-1;
}
/* Preserve only complete records, including after an interrupted legacy append. */
static int load_tail(size_t *count,int *had_current) {
    *count=0; *had_current=present(TL_CUR);
    if(*had_current<0) return WB_E_IO;
    const char *p=TL_CUR;
    if(!*had_current) {
        int backup=present(TL_OLD);
        if(backup<=0)return backup==0?WB_OK:WB_E_IO;
        p=TL_OLD;
    }
    wb_reader rd;wb_vfile f;
    if(wb_vita_reader_open(p,&rd,&f)!=WB_OK)return WB_E_IO;
    size_t n=rd.size>TL_MAX?TL_MAX:(size_t)rd.size;uint64_t start=rd.size-n;
    int rc=n?rd.read_at(rd.ctx,start,history,n):WB_OK;
    wb_vita_reader_close(&f);
    if(rc!=WB_OK)return WB_E_IO;
    size_t lo=0;
    if(start) {while(lo<n && history[lo]!='\n')lo++;if(lo<n)lo++;}
    while(n>lo && history[n-1]!='\n')n--;
    *count=n-lo; memmove(history,history+lo,*count);return WB_OK;
}
typedef struct {
    int (*wr)(int,const void *,SceSize);
    int (*sync)(int,int);
    int (*close)(int);
} tl_ops;
/* A short/failed write or sync/close error never publishes the new generation. */
static int commit_bytes(const tl_ops *io,int fd,const char *data,size_t n) {
    int ok=fd>=0 && io->wr(fd,data,(SceSize)n)==(int)n && io->sync(fd,0)>=0;
    if(fd>=0 && io->close(fd)<0)ok=0;
    return ok?WB_OK:WB_E_IO;
}
static const tl_ops vita_ops={sceIoWrite,sceIoSyncByFd,sceIoClose};
static int append_line(const char *stage,const char *version,const char *run) {
    size_t n=0;int cur=0;
    if(!stage || !*stage)return WB_E_ARG;
    int rc=load_tail(&n,&cur);
    if(rc!=WB_OK)return rc;
    int len=snprintf(history+n,sizeof history-n,"stage=%s ver=%s run=%s ms=%" PRIu64 "\n",
        stage,version&&*version?version:"-",run&&*run?run:"-",(uint64_t)(sceKernelGetProcessTimeWide()/1000u));
    if(len<=0 || len>=TL_LINE)return WB_E_LIMIT;
    int fd=sceIoOpen(TL_NEW,SCE_O_CREAT|SCE_O_WRONLY|SCE_O_TRUNC,0666);
    rc=commit_bytes(&vita_ops,fd,history,n+(size_t)len);
    if(rc!=WB_OK){(void)sceIoRemove(TL_NEW);return rc;}
    /* Retain a committed generation across both renames. Do not remove
     * the sole backup if a previous invocation stopped between those renames. */
    if(cur) {
        int dr=sceIoRemove(TL_OLD);
        if((dr<0 && !absent(dr)) || sceIoRename(TL_CUR,TL_OLD)<0)return WB_E_IO;
    }
    if(sceIoRename(TL_NEW,TL_CUR)<0) {
        if(cur)(void)sceIoRename(TL_OLD,TL_CUR);
        return WB_E_IO;
    }
    return WB_OK;
}
int wb_timeline_note(const char *stage,const char *version,const char *run) {
    last_error=append_line(stage,version,run);return last_error;
}
int wb_timeline_dump(wb_out *out,unsigned max_lines) {
    size_t n=0;int cur;
    if(load_tail(&n,&cur)!=WB_OK){(void)wb_out_puts(out,"ERR timeline-read\n");return WB_E_IO;}
    unsigned lines=0;size_t start=n;
    while(start>0 && lines<max_lines) {
        --start;
        if(start==0 || history[start-1]=='\n')++lines;
    }
    if(n>start){if(out->write(out->ctx,history+start,n-start)!=WB_OK)return WB_E_IO;}
    else if(wb_out_puts(out,"timeline empty\n")!=WB_OK)return WB_E_IO;
    if(last_error){(void)wb_out_puts(out,"ERR timeline-not-saved\n");return last_error;}
    return WB_OK;
}
/* Fixed in-memory probes exercise the SAME commit function. No caller-controlled
 * fault or path, no device writes, no live timeline or authorization changes. */
static struct { int mode, writes, syncs, closes; } mock;
static int tw(int fd,const void *p,SceSize n){(void)fd;(void)p;mock.writes++;return mock.mode==1?(int)n-1:(int)n;}
static int ts(int fd,int unused){(void)fd;(void)unused;mock.syncs++;return mock.mode==2?-1:0;}
static int tc(int fd){(void)fd;mock.closes++;return mock.mode==3?-1:0;}
unsigned wb_timeline_selftest(void) {
    const tl_ops test={tw,ts,tc};unsigned count=0;
    for(int mode=0;mode<4;mode++){
        memset(&mock,0,sizeof mock);mock.mode=mode;
        int rc=commit_bytes(&test,1,"x\n",2);
        count+=((rc==WB_OK)==(mode==0)) && mock.writes==1 && mock.syncs==(mode!=1) && mock.closes==1;
    }
    return count;
}

