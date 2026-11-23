/* Native device I/O fixture. No real Vita, network, files or privileged APIs. */
#include "wb_sftp_vita.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define ROOT "ux0:/VITA-POC"
enum { MOUNT=1, INCOMING=2, SUB=3, BINARY=4 };
#define DIR 0x1000u /* existing SDK stub mode values */
#define REG 0x2000u
#define SPECIAL 0x4000u
static struct { int live,idx,pos; } handle[16];
static int live_count,dir_opens,file_opens,dreads,bad_zero,bad_lookup;
static int close_error,io_error,root_special,too_many;
static const uint8_t binary[]={0x00,0xff,0x42,0x0d,0x0a,0,0x80,0x21};

static int makefd(int idx) {
    for(int i=0;i<16;i++) if(!handle[i].live) {
        handle[i].live=1;handle[i].idx=idx;handle[i].pos=0;live_count++;return i;
    }
    return -1;
}
static int drop(int fd) {
    assert(fd>=0 && fd<16 && handle[fd].live);
    handle[fd].live=0;live_count--;
    if(close_error){close_error--;return -1;}
    return 0;
}
int sceIoDclose(int fd) {return drop(fd);}
int sceIoClose(int fd) {return drop(fd);}
int sceIoDopen(const char *path) {
    dir_opens++;
    if(strcmp(path,"ux0:/")==0) return makefd(MOUNT);
    if(strcmp(path,ROOT)==0) return makefd(INCOMING);
    if(strcmp(path,ROOT "/sub")==0) return makefd(SUB);
    bad_lookup++;
    return (int)0x80010002u;
}
int sceIoOpen(const char *path,int flags,SceMode mode) {
    assert(flags==SCE_O_RDONLY && mode==0);
    file_opens++;
    if(strcmp(path,ROOT "/sub/binary.bin")==0) return makefd(BINARY);
    bad_lookup++;
    return (int)0x80010002u;
}
SceOff sceIoLseek(int fd,SceOff off,int whence) {
    assert(fd>=0 && fd<16 && handle[fd].live && handle[fd].idx==BINARY);
    if(io_error) return -1;
    if(whence==SCE_SEEK_END) return handle[fd].pos=(int)sizeof binary;
    if(whence!=SCE_SEEK_SET || off<0 || off>2147483647) return -1;
    handle[fd].pos=(int)off;return off;
}
int sceIoRead(int fd,void *buf,SceSize n) {
    assert(handle[fd].idx==BINARY && handle[fd].live);
    if(io_error) return -1;
    size_t at=(size_t)handle[fd].pos;
    if(at>=sizeof binary) return 0;
    if(n>sizeof binary-at) n=(SceSize)(sizeof binary-at);
    memcpy(buf,binary+at,n);handle[fd].pos+=(int)n;return (int)n;
}
static int ent(SceIoDirent *e,const char *name,SceMode mode,SceOff size) {
    strcpy(e->d_name,name);e->d_stat.st_mode=mode;e->d_stat.st_size=size;return 1;
}
int sceIoDread(int fd,SceIoDirent *e) {
    for(size_t k=0;k<sizeof *e;k++) if(((unsigned char*)e)[k]){bad_zero++;break;}
    assert(fd>=0 && fd<16 && handle[fd].live);
    dreads++;int at=handle[fd].pos++;
    if(io_error) return -1;
    switch(handle[fd].idx) {
    case MOUNT:
        return at?0:ent(e,"VITA-POC",root_special?SPECIAL:DIR,0);
    case INCOMING:
        if(too_many) return ent(e,"unrelated",REG,1);
        if(at==0) return ent(e,"sub",DIR,0);
        if(at==1) return ent(e,"special",SPECIAL,0);
        return 0;
    case SUB:
        switch(at) {
        case 0:return ent(e,".",DIR,0);
        case 1:return ent(e,"..",DIR,0);
        case 2:return ent(e,"binary.bin",REG,sizeof binary);
        default:return 0;
        }
    default:assert(0);return -1;
    }
}
int main(void) {
    const wb_sftp_ops *o=&wb_sftp_vita_ops;
    int fd=-1,d=-1;wb_sftp_attr a={0};char name[101];uint8_t buf[32];size_t got=0;
    assert(o->stat(NULL,"/",&a)==WB_SFTP_OK && a.is_dir && a.mtime==0);
    assert(o->stat(NULL,"/sub/binary.bin",&a)==WB_SFTP_OK && !a.is_dir && a.size==sizeof binary);
    assert(o->open(NULL,"/sub",1,&d)==0);
    assert(o->readdir(NULL,d,name,sizeof name,&a)==0 && strcmp(name,"binary.bin")==0 && !a.is_dir);
    assert(o->readdir(NULL,d,name,sizeof name,&a)==WB_SFTP_EOF);
    assert(o->fstat(NULL,d,1,&a)==0 && a.is_dir);
    assert(o->close(NULL,d,1)==0);
    assert(o->open(NULL,"/sub/binary.bin",0,&fd)==0);
    assert(o->fstat(NULL,fd,0,&a)==0 && a.size==sizeof binary);
    assert(o->read(NULL,fd,3,buf,3,&got)==0 && got==3 && !memcmp(buf,binary+3,3));
    assert(o->read(NULL,fd,0,buf,sizeof buf,&got)==0 && got==sizeof binary && !memcmp(buf,binary,got));
    printf("native file bytes: ");for(size_t i=0;i<got;i++)printf("%02x",buf[i]);puts("");
    assert(o->read(NULL,fd,99,buf,1,&got)==WB_SFTP_EOF && !got);
    assert(o->read(NULL,fd,UINT64_MAX,buf,1,&got)==WB_SFTP_FAILURE);
    io_error=1;assert(o->read(NULL,fd,0,buf,1,&got)==WB_SFTP_FAILURE);io_error=0;
    assert(o->close(NULL,fd,0)==0 && !live_count);
    const char *bad[]={NULL,"","relative","/../private","/sub/./x","/sub//x",
                       "/sub/x/","/ux0:data","/sub/a\\b","/sub/trailing.","/sub/name "};
    int before=dir_opens;
    for(size_t i=0;i<sizeof bad/sizeof *bad;i++) assert(o->stat(NULL,bad[i],&a)==WB_SFTP_DENIED);
    assert(dir_opens==before && file_opens==1);
    assert(o->open(NULL,"/sub",0,&fd)==WB_SFTP_DENIED && fd==-1);
    assert(o->open(NULL,"/missing",0,&fd)==WB_SFTP_NO_FILE && fd==-1);
    assert(o->open(NULL,"/special/ordinary",0,&fd)==WB_SFTP_DENIED && !live_count);
    assert(o->open(NULL,"/special",0,&fd)==WB_SFTP_DENIED && !live_count);
    root_special=1;
    assert(o->open(NULL,"/sub/binary.bin",0,&fd)==WB_SFTP_DENIED && !live_count);
    root_special=0;close_error=1;
    assert(o->stat(NULL,"/",&a)==WB_SFTP_FAILURE && !live_count);
    too_many=1;int old=dreads;
    assert(o->stat(NULL,"/missing",&a)==WB_SFTP_FAILURE && dreads-old<=512 && !live_count);
    assert(!bad_zero && !bad_lookup && file_opens==1);
    puts("PASS: virtual root, binary range/read + FSTAT, READDIR, missing/path/type denials, I/O faults, scan budget, all handles closed");
    return 0;
}
