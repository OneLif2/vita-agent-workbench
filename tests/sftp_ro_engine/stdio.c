/* Host-only synthetic directory. No SSH connection, file reads or Vita calls. */
#include "wb_sftp_ro.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
typedef struct {int used,dir,index;} file;
static file files[WB_SFTP_HANDLES];
static const char filename[]="settings.bin";
enum { FIXSIZE=70123 };
static int fsstat(void *ctx,const char *p,wb_sftp_attr *a){
    (void)ctx;
    if(!strcmp(p,"/")||!strcmp(p,"/samples")){*a=(wb_sftp_attr){0,1700000000,1};return 0;}
    if(!strcmp(p,"/samples/settings.bin")){*a=(wb_sftp_attr){FIXSIZE,1700000000,0};return 0;}
    return WB_SFTP_NO_FILE;
}
static int fsopen(void *ctx,const char *p,int dir,int *fd){
    wb_sftp_attr a;int rc=fsstat(ctx,p,&a);
    if(rc||dir!=a.is_dir)return WB_SFTP_NO_FILE;
    for(int i=0;i<WB_SFTP_HANDLES;i++)if(!files[i].used){
        files[i]=(file){1,dir,p[1]?1:0};*fd=i;return 0;
    }
    return WB_SFTP_FAILURE;
}
static int fsclose(void *ctx,int fd,int dir){
    (void)ctx;(void)dir;files[fd].used=0;return 0;
}
static int fsread(void *ctx,int fd,uint64_t off,uint8_t *buf,size_t cap,size_t *got){
    (void)ctx;(void)fd;*got=0;
    if(off>=FIXSIZE)return WB_SFTP_EOF;
    size_t n=(size_t)(FIXSIZE-off);if(n>cap)n=cap;
    for(size_t i=0;i<n;i++)buf[i]=(uint8_t)((off+i)%251u);
    *got=n;return 0;
}
static int fsnext(void *ctx,int fd,char *name,size_t cap,wb_sftp_attr *a){
    int i=files[fd].index;
    if(i<0)return WB_SFTP_EOF;
    const char *text=i?filename:"samples";
    if(strlen(text)>=cap)return WB_SFTP_FAILURE;
    strcpy(name,text);files[fd].index=-1;
    return fsstat(ctx,i?"/samples/settings.bin":"/samples",a);
}
static int fsfstat(void *ctx,int fd,int isdir,wb_sftp_attr *a){
    (void)fd;return fsstat(ctx,isdir?"/samples":"/samples/settings.bin",a);
}
int main(void){
#ifdef _WIN32
    _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
    static const wb_sftp_ops ops={NULL,fsstat,fsopen,fsclose,fsread,fsnext,fsfstat};
    static uint8_t b[WB_SFTP_PACKET_MAX],o[WB_SFTP_REPLY_MAX];
    wb_sftp_ro engine;wb_sftp_init(&engine,&ops);
    uint8_t d[4];size_t wr;
    while(fread(d,1,4,stdin)==4){
        size_t n=((uint32_t)d[0]<<24)|((uint32_t)d[1]<<16)|((uint32_t)d[2]<<8)|d[3];
        if(n>sizeof b||fread(b,1,n,stdin)!=n||wb_sftp_reply(&engine,b,n,o,sizeof o,&wr))break;
        d[0]=(uint8_t)(wr>>24);d[1]=(uint8_t)(wr>>16);d[2]=(uint8_t)(wr>>8);d[3]=(uint8_t)wr;
        if(fwrite(d,1,4,stdout)!=4||fwrite(o,1,wr,stdout)!=wr||fflush(stdout))break;
    }
    wb_sftp_reset(&engine);
    for(int i=0;i<WB_SFTP_HANDLES;i++)if(files[i].used)return 1;
    return 0;
}
