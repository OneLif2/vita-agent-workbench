#ifndef WB_APP_SPOOL_VITA_H
#define WB_APP_SPOOL_VITA_H
#include "wb_app_spool.h"
#include "wb_vita_io.h"
#include <stdio.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>

typedef struct {char dir[128],path[160];int write_fd;wb_vfile read_file;bool owned;} wb_app_spool_file;
static int wb_app_disk_dispose(void *handle) {
    wb_app_spool_file *f=handle;int rc=WB_OK;
    if(f->write_fd>=0 && sceIoClose(f->write_fd)<0)rc=WB_E_IO;
    if(f->read_file.fd>=0)wb_vita_reader_close(&f->read_file);
    if(f->owned){
        int x=sceIoRemove(f->path);
        if(x<0 && (uint32_t)x!=UINT32_C(0x80010002))rc=WB_E_IO;
        if(sceIoRmdir(f->dir)<0)rc=WB_E_IO;
    }
    free(f);return rc;
}
static int wb_app_disk_begin(void *ctx,uint64_t size,void **handle) {
    (void)ctx;(void)size;*handle=NULL;
    wb_app_spool_file *f=calloc(1,sizeof *f);if(!f)return WB_E_NOMEM;
    f->write_fd=-1;f->read_file.fd=-1;
    int rc=wb_vita_mkdir_p(WB_ROOT "/stage");
    if(rc!=WB_OK){free(f);return rc;}
    static uint32_t serial;
    for(unsigned tries=0;tries<64;tries++){
        const int n=snprintf(f->dir,sizeof f->dir,WB_ROOT "/stage/.app-snapshot-%016llx-%08x",
                         (unsigned long long)sceKernelGetProcessTimeWide(),++serial);
        if(n<0 || (size_t)n>=sizeof f->dir){free(f);return WB_E_PATH;}
        rc=sceIoMkdir(f->dir,0777);
        if(rc==0){f->owned=true;break;}
        if((uint32_t)rc!=UINT32_C(0x80010011)){free(f);return WB_E_IO;}
    }
    if(!f->owned){free(f);return WB_E_STAGE;}
    const int n=snprintf(f->path,sizeof f->path,"%s/archive.vpk",f->dir);
    if(n<0 || (size_t)n>=sizeof f->path){(void)sceIoRmdir(f->dir);free(f);return WB_E_PATH;}
    /* No O_EXCL: it is unsupported by the observed Vita filesystem. The
     * successful exclusive mkdir owns this fresh namespace instead.
     * SceIoAccessMode keeps system RW in the low bits. 0600 leaves them
     * clear, and sceIoOpen then fails on hardware before any byte is copied.
     * 0666 matches the other Vita writers in wb_vita_io.c. */
    f->write_fd=sceIoOpen(f->path,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0666);
    if(f->write_fd<0){(void)wb_app_disk_dispose(f);return WB_E_IO;}
    *handle=f;return WB_OK;
}
static int wb_app_disk_write(void *handle,const void *bytes,size_t n) {
    wb_app_spool_file *f=handle;size_t at=0;
    while(at<n){int k=sceIoWrite(f->write_fd,(const uint8_t *)bytes+at,(SceSize)(n-at));
        if(k<=0 || (size_t)k>n-at)return WB_E_IO;
        at+=(size_t)k;
    }
    return WB_OK;
}
static int wb_app_disk_finish(void *handle,wb_reader *reader) {
    wb_app_spool_file *f=handle;
    if(sceIoSyncByFd(f->write_fd,0)<0)return WB_E_IO;
    const int rc=sceIoClose(f->write_fd);f->write_fd=-1;if(rc<0)return WB_E_IO;
    return wb_vita_reader_open(f->path,reader,&f->read_file);
}
static const wb_app_spool_ops wb_app_disk_ops={NULL,wb_app_disk_begin,wb_app_disk_write,wb_app_disk_finish,wb_app_disk_dispose};
#define WB_APP_IO_OPS (&wb_app_disk_ops)
#endif
