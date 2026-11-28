/* Production native adapter + production Vita reader; only SDK syscalls are
 * modeled. This model enforces unsafe-homebrew SYSTEM RW (0006), not POSIX
 * owner permission. It does not constitute real-device acceptance. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/io/dirent.h>
#include "wb_err.h"
#include "wb_sha256.h"

#define WB_ROOT "ux0:data/INAP00018"
enum { NATIVE_ENOENT=(int)0x80010002u, NATIVE_EACCES=(int)0x8001000du,
       NATIVE_EEXIST=(int)0x80010011u, NATIVE_EIO=(int)0x80010005u };
enum { INPUT_SIZE=65573, STORE_CAP=70000 };
static const char *scenario;
static size_t live_allocs,allocated_bytes;
typedef union {max_align_t align;size_t size;} allocation;
static void *tracked_malloc(size_t n){
    allocation *a=malloc(sizeof *a+n);if(!a)return NULL;
    a->size=n;live_allocs++;allocated_bytes+=n;return a+1;
}
static void *tracked_calloc(size_t n,size_t size){
    if(!strcmp(scenario,"alloc-fail"))return NULL;
    if(size&&n>SIZE_MAX/size)return NULL;
    void *p=tracked_malloc(n*size);if(p)memset(p,0,n*size);return p;
}
static void tracked_free(void *p){
    if(p){allocation *a=(allocation *)p-1;assert(live_allocs&&allocated_bytes>=a->size);
        live_allocs--;allocated_bytes-=a->size;free(a);}
}
#define malloc tracked_malloc
#define calloc tracked_calloc
#define free tracked_free
#include "wb_app_spool_vita.h"
#undef malloc
#undef calloc
#undef free

static unsigned char source[INPUT_SIZE],stored[STORE_CAP];
static char owned_dir[128],owned_path[160],foreign[64][128];
static bool own_dir_exists,file_exists;
static size_t stored_size;
static unsigned mkdir_calls,foreign_count,open_calls,write_calls,sync_calls,
                close_calls,read_calls,remove_calls,rmdir_calls,handles_open;
static unsigned mode_seen,flags_seen;
static bool sync_seen,write_close_seen;
typedef struct {bool open,write;size_t pos;} descriptor;
static descriptor fds[16];
static bool fault(const char *name){return !strcmp(scenario,name);}
static bool snapshot(const char *path){return !strncmp(path,WB_ROOT "/stage/.app-snapshot-",sizeof(WB_ROOT "/stage/.app-snapshot-")-1);}
static bool system_rw(SceMode mode){return (mode&0006u)==0006u;}
static void foreign_untouched(const char *path){
    for(unsigned i=0;i<foreign_count;i++)assert(strcmp(path,foreign[i]));
}
static int newfd(bool write){
    for(int i=3;i<16;i++)if(!fds[i].open){fds[i]=(descriptor){true,write,0};handles_open++;return i;}
    abort();
}
uint64_t sceKernelGetProcessTimeWide(void){return UINT64_C(0x123456789abcdef);}
int sceIoMkdir(const char *path,SceMode mode){
    assert(mode==0777);mkdir_calls++;
    if(!snapshot(path)){
        if(fault("mkdir-root-fail")&&!strcmp(path,WB_ROOT "/stage"))return NATIVE_EIO;
        return NATIVE_EEXIST;
    }
    if(fault("mkdir-fail"))return NATIVE_EIO;
    if(fault("collisions")|| (fault("one-collision")&&!foreign_count)){
        assert(foreign_count<64);strcpy(foreign[foreign_count++],path);return NATIVE_EEXIST;
    }
    assert(!own_dir_exists);strcpy(owned_dir,path);own_dir_exists=true;return 0;
}
int sceIoGetstat(const char *path,SceIoStat *st){
    memset(st,0,sizeof *st);
    if(fault("mkdir-root-fail")&&!strcmp(path,WB_ROOT "/stage"))return NATIVE_EIO;
    if(!snapshot(path)){st->st_mode=0010000|0777;return 0;}
    return NATIVE_ENOENT;
}
SceUID sceIoOpen(const char *path,int flags,SceMode mode){
    open_calls++;assert(snapshot(path));
    if(flags&SCE_O_WRONLY){
        mode_seen=mode;flags_seen=(unsigned)flags;
        assert(flags==(SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC));
        assert(own_dir_exists&&!file_exists);
        assert(!strncmp(path,owned_dir,strlen(owned_dir))&&!strcmp(path+strlen(owned_dir),"/archive.vpk"));
        if(!system_rw(mode)||fault("open-fail"))return NATIVE_EACCES;
        strcpy(owned_path,path);file_exists=true;stored_size=0;return newfd(true);
    }
    assert(flags==SCE_O_RDONLY&&mode==0);
    assert(file_exists&&!strcmp(path,owned_path)&&sync_seen&&write_close_seen);
    if(fault("reopen-fail"))return NATIVE_EIO;
    return newfd(false);
}
int sceIoWrite(SceUID fd,const void *data,SceSize n){
    assert(fd>=3&&fd<16&&fds[fd].open&&fds[fd].write);write_calls++;
    if(fault("write-fail"))return NATIVE_EIO;
    if(fault("zero-write"))return 0;
    if(fault("oversize-write"))return (int)n+1;
    size_t take=n;if(take>4096)take=4096;assert(fds[fd].pos+take<=sizeof stored);
    memcpy(stored+fds[fd].pos,data,take);fds[fd].pos+=take;if(fds[fd].pos>stored_size)stored_size=fds[fd].pos;
    return (int)take;
}
int sceIoSyncByFd(SceUID fd,int ignored){
    assert(fd>=3&&fd<16&&fds[fd].open&&fds[fd].write&&ignored==0);sync_calls++;
    if(fault("sync-fail"))return NATIVE_EIO;
    sync_seen=true;return 0;
}
int sceIoClose(SceUID fd){
    assert(fd>=3&&fd<16&&fds[fd].open);bool writing=fds[fd].write;
    fds[fd].open=false;handles_open--;close_calls++;if(writing)write_close_seen=true;
    /* Explicit error-after-retire model. No claim about Vita FD state after
     * a negative close, and no unsafe retry of an ambiguous native close. */
    return writing&&fault("close-reports-error")?NATIVE_EIO:0;
}
SceOff sceIoLseek(SceUID fd,SceOff off,int whence){
    assert(fd>=3&&fd<16&&fds[fd].open&&!fds[fd].write);
    if(fault("seek-fail"))return NATIVE_EIO;
    assert(off>=0);uint64_t pos=whence==SCE_SEEK_END?stored_size+(uint64_t)off:(uint64_t)off;
    assert(pos<=stored_size);fds[fd].pos=(size_t)pos;return (SceOff)pos;
}
int sceIoRead(SceUID fd,void *data,SceSize n){
    assert(fd>=3&&fd<16&&fds[fd].open&&!fds[fd].write);read_calls++;
    if(fault("readback-fail"))return NATIVE_EIO;
    size_t take=stored_size-fds[fd].pos;if(take>n)take=n;if(take>1007)take=1007;
    memcpy(data,stored+fds[fd].pos,take);fds[fd].pos+=take;return (int)take;
}
int sceIoRemove(const char *path){
    foreign_untouched(path);remove_calls++;assert(own_dir_exists);
    assert(!strncmp(path,owned_dir,strlen(owned_dir))&&!strcmp(path+strlen(owned_dir),"/archive.vpk"));
    if(!file_exists)return NATIVE_ENOENT;
    if(fault("remove-fail"))return NATIVE_EIO;
    file_exists=false;return 0;
}
int sceIoRmdir(const char *path){
    foreign_untouched(path);rmdir_calls++;assert(!strcmp(path,owned_dir)&&own_dir_exists);
    if(fault("rmdir-fail")||file_exists)return NATIVE_EIO;
    own_dir_exists=false;return 0;
}
SceUID sceIoDopen(const char *path){(void)path;abort();}
int sceIoDread(SceUID fd,SceIoDirent *entry){(void)fd;(void)entry;abort();}
int sceIoDclose(SceUID fd){(void)fd;abort();}

static int source_read(const void *ctx,uint64_t off,void *data,size_t n){
    (void)ctx;if(off>sizeof source||n>sizeof source-off)return WB_E_IO;
    if(fault("source-read-fail"))return WB_E_IO;
    memcpy(data,source+(size_t)off,n);return WB_OK;
}
int main(int argc,char **argv){
    assert(argc==2);scenario=argv[1];bool probe=fault("--probe");if(probe)scenario="success";
    for(size_t i=0;i<sizeof source;i++)source[i]=(unsigned char)(i*17u+3u);
    wb_reader src={.ctx=NULL,.size=sizeof source,.read_at=source_read};wb_app_spool spool;
    int rc=wb_app_spool_copy(&spool,&src,&wb_app_disk_ops,NULL,NULL);int dispose=WB_OK;
    if(probe){
        if(rc==WB_OK)dispose=wb_app_spool_dispose(&spool);
        assert(live_allocs==0&&allocated_bytes==0&&handles_open==0&&!own_dir_exists&&!file_exists);
        printf("native-spool rc=%d mode=%04o system_rw=%d bytes_written=%zu write_calls=%u dispose=%d handles=%u\n",rc,mode_seen,system_rw(mode_seen),stored_size,write_calls,dispose,handles_open);
        return 0;
    }
    bool success=fault("success")||fault("one-collision")||fault("readback-fail")||fault("remove-fail")||fault("rmdir-fail");
    if(success){
        assert(rc==WB_OK&&mode_seen==0666&&flags_seen==(SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC));
        assert(stored_size==sizeof source&&write_calls>2&&sync_calls==1&&close_calls==1);
        uint8_t got[INPUT_SIZE];int read=spool.reader.read_at(spool.reader.ctx,0,got,sizeof got);
        if(fault("readback-fail"))assert(read==WB_E_IO);
        else assert(read==WB_OK&&!memcmp(got,source,sizeof source));
        dispose=wb_app_spool_dispose(&spool);
        assert(dispose==((fault("remove-fail")||fault("rmdir-fail"))?WB_E_IO:WB_OK));
    }else assert(rc!=WB_OK);
    assert(handles_open==0&&live_allocs==0&&allocated_bytes==0);
    if(fault("remove-fail"))assert(file_exists&&own_dir_exists);
    else if(fault("rmdir-fail"))assert(!file_exists&&own_dir_exists);
    else assert(!file_exists&&!own_dir_exists);
    if(fault("collisions"))assert(foreign_count==64&&remove_calls==0&&rmdir_calls==0&&open_calls==0);
    if(fault("one-collision"))assert(foreign_count==1);
    printf("PASS native-adapter %s rc=%d mode=%04o system_rw=%d copied=%zu writes=%u sync=%u reads=%u closes=%u live=%u foreign=%u dispose=%d\n",
      scenario,rc,mode_seen,system_rw(mode_seen),stored_size,write_calls,sync_calls,read_calls,close_calls,handles_open,foreign_count,dispose);
    return 0;
}
