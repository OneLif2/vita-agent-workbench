/* Local, disposable host filesystem beneath WB_SCP_TEST_FS; no device,
   subprocess, shell, or network. Production SFTP engine & framing linked by run.py. */
#include "wb_sftp_frame.h"
#include "wb_sftp_vita.h"
#include "wb_tty_file.h"
#include "wb_ver.h"
#include <stdlib.h>
#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
/* Read service below uses a host filesystem fixture; the real write wrapper
 * must call the shared storage adapter, NOT the read adapter or native I/O. */
SceUID sceIoDopen(const char *p){(void)p;abort();}
int sceIoDread(SceUID f,SceIoDirent *d){(void)f;(void)d;abort();}
int sceIoDclose(SceUID f){(void)f;abort();}
SceUID sceIoOpen(const char *p,int f,SceMode m){(void)p;(void)f;(void)m;abort();}
int sceIoClose(SceUID f){(void)f;abort();}
int sceIoRead(SceUID f,void *b,SceSize n){(void)f;(void)b;(void)n;abort();}
SceOff sceIoLseek(SceUID f,SceOff off,int w){(void)f;(void)off;(void)w;abort();}
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#define makedir(path) _mkdir(path)
#define sysread _read
#define syswrite _write
#else
#include <unistd.h>
#define makedir(path) mkdir(path,0700)
#define sysread read
#define syswrite write
#endif
enum {MAXP=1024};
static const char *root;
typedef struct {DIR *dir;FILE *file;char path[MAXP];} fd;
static fd files[WB_SFTP_HANDLES];
static int join(const char *v,char full[MAXP]){
    if(!v||v[0]!='/'||strstr(v,"..")||strchr(v,'\\')||strchr(v,':'))return 0;
    return snprintf(full,MAXP,"%s%s",root,v)<MAXP;
}
static int details(const char *full,wb_sftp_attr *a){
    struct stat st;
    if(stat(full,&st))return errno==ENOENT?WB_SFTP_NO_FILE:WB_SFTP_FAILURE;
    a->is_dir=S_ISDIR(st.st_mode);a->size=a->is_dir?0:(uint64_t)st.st_size;a->mtime=0;
    return WB_SFTP_OK;
}
static int info(void *ctx,const char *v,wb_sftp_attr *a){
    (void)ctx;char full[MAXP];return join(v,full)?details(full,a):WB_SFTP_DENIED;
}
static int op(void *ctx,const char *v,int dir,int *out){
    (void)ctx;char full[MAXP];wb_sftp_attr a;
    if(!join(v,full)||details(full,&a)||a.is_dir!=dir)return WB_SFTP_DENIED;
    for(int i=0;i<WB_SFTP_HANDLES;i++){
        fd *f=files+i;if(f->dir||f->file)continue;
        if(dir)f->dir=opendir(full);else f->file=fopen(full,"rb");
        if(!f->dir&&!f->file)return WB_SFTP_FAILURE;
        strcpy(f->path,full);*out=i;return WB_SFTP_OK;
    }return WB_SFTP_FAILURE;
}
static int cl(void *ctx,int i,int dir){
    (void)ctx;int rc=dir?closedir(files[i].dir):fclose(files[i].file);
    memset(files+i,0,sizeof files[i]);return rc?WB_SFTP_FAILURE:WB_SFTP_OK;
}
static int rd(void *ctx,int i,uint64_t off,uint8_t *b,size_t n,size_t *got){
    (void)ctx;if(off>0x7fffffff||fseek(files[i].file,(long)off,SEEK_SET))return WB_SFTP_FAILURE;
    *got=fread(b,1,n,files[i].file);return ferror(files[i].file)?WB_SFTP_FAILURE:WB_SFTP_OK;
}
static int next(void *ctx,int i,char *name,size_t len,wb_sftp_attr *a){
    (void)ctx;struct dirent *d;fd *f=files+i;
    while((d=readdir(f->dir))!=NULL){
        if(!strcmp(d->d_name,".")||!strcmp(d->d_name,".."))continue;
        char full[MAXP];if(strlen(d->d_name)>=len||snprintf(full,sizeof full,"%s/%s",f->path,d->d_name)>=MAXP)return WB_SFTP_FAILURE;
        strcpy(name,d->d_name);return details(full,a);
    }return WB_SFTP_EOF;
}
static int fs(void *ctx,int i,int dir,wb_sftp_attr *a){(void)ctx;(void)dir;return details(files[i].path,a);}
typedef struct{FILE *tmp;char path[MAXP];} up;
static int create(void *ctx,const char *v,void **handle){
    (void)ctx;up *u=calloc(1,sizeof *u);wb_sftp_attr a;
    if(!u)return WB_SFTP_FAILURE;
    if(!join(v,u->path)||details(u->path,&a)!=WB_SFTP_NO_FILE){free(u);return WB_SFTP_DENIED;}
    u->tmp=tmpfile();if(!u->tmp){free(u);return WB_SFTP_FAILURE;}
    *handle=u;return WB_SFTP_OK;
}
static int add(void *ctx,void *handle,const uint8_t *b,size_t n){(void)ctx;up *u=handle;return fwrite(b,1,n,u->tmp)==n?WB_SFTP_OK:WB_SFTP_FAILURE;}
static int finish(void *ctx,void *handle,int commit,const char *wire_hash){
    (void)ctx;up *u=handle;int rc=WB_SFTP_OK;
    if(commit){
        /* Test the actual release wrapper's SHA-256 finalization against
         * a fresh read of all the bytes in private staging, before publish. */
        wb_sha256 sha;wb_sha256_init(&sha);
        uint8_t b[4096],raw[32];size_t n;rewind(u->tmp);
        while((n=fread(b,1,sizeof b,u->tmp))!=0)wb_sha256_update(&sha,b,n);
        wb_sha256_final(&sha,raw);char hex[65];wb_sha_hex(raw,32,hex);
        if(!wire_hash||strcmp(hex,wire_hash)||getenv("WB_SCP_FAULT_SHA")){fclose(u->tmp);free(u);return WB_SFTP_FAILURE;}
        struct stat st;FILE *f;
        if(!stat(u->path,&st)||errno!=ENOENT)rc=WB_SFTP_DENIED;
        else if(!(f=fopen(u->path,"wb")))rc=WB_SFTP_FAILURE;
        else{
            uint8_t b[8192];size_t n;rewind(u->tmp);
            while((n=fread(b,1,sizeof b,u->tmp))!=0)if(fwrite(b,1,n,f)!=n){rc=WB_SFTP_FAILURE;break;}
            if(ferror(u->tmp)||fclose(f))rc=WB_SFTP_FAILURE;
        }
    }
    fclose(u->tmp);free(u);return rc;
}
static int mk(void *ctx,const char *v){(void)ctx;char full[MAXP];return join(v,full)&&makedir(full)==0?WB_SFTP_OK:WB_SFTP_FAILURE;}
/* Only the underlying storage adapter is substituted. All WB wire path
 * mapping, SHA streaming and commit/abort choices use release C code. */
static const char *virtual_name(const char *absolute){
    return !strncmp(absolute,WB_INCOMING "/",sizeof WB_INCOMING)?absolute+sizeof WB_INCOMING-1:NULL;
}
const char *wb_tty_vopen_stream(const char *p,void **out){
    const char *v=virtual_name(p);return v && !create(NULL,v,out)?NULL:"create-denied";
}
const char *wb_tty_vwrite(void *h,const uint8_t *b,size_t n){return add(NULL,h,b,n)?"write-error":NULL;}
const char *wb_tty_vfinish(void *h,bool commit,const char *hash){return finish(NULL,h,commit,hash)?"publish-denied":NULL;}
const char *wb_tty_vmkdir(const char *p){
    const char *v=virtual_name(p);return v && !mk(NULL,v)?NULL:"mkdir-denied";
}
static int wire_rd(void *ctx,uint8_t *data,size_t cap){
    (void)ctx;int n=(int)sysread(0,data,(unsigned)(cap>1021?1021:cap));return n?n:-2;
}
static int wire_wr(void *ctx,const uint8_t *data,size_t n){
    (void)ctx;return (int)syswrite(1,data,(unsigned)(n>1021?1021:n));
}
int main(void){
#ifdef _WIN32
    _setmode(0,_O_BINARY);_setmode(1,_O_BINARY);
#endif
    root=getenv("WB_SCP_TEST_FS");if(!root||!*root)return 2;
    static const wb_sftp_ops read_ops={NULL,info,op,cl,rd,next,fs};
    static wb_sftp_frame f;wb_sftp_init(&f.engine,&read_ops);wb_sftp_enable_write(&f.engine,&wb_sftp_vita_write_ops);
    int rc;while((rc=wb_sf_pump(&f,NULL,wire_rd,wire_wr))==1){}
    wb_sftp_reset(&f.engine);return rc?1:0;
}
