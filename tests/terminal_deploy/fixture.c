#include <assert.h>
#include <stdio.h>
#include "wb_ver.h"
#include "wb_out.h"
#include "wb_path.h"
#include "wb_str.h"
#include "wb_checked_hash.h"
typedef struct {int live;} wb_vfile;
static struct {char payload_ver[32];} a;
static unsigned char input[20162],copy[20162];
static const char *srcpath=WB_INCOMING "/flashed.suprx";
static unsigned opened,swapped,removed,stage_bytes,mode;
static char reply[200];
static int emit(void *ctx,const char *txt,size_t n){
    (void)ctx;assert(n<sizeof reply);memcpy(reply,txt,n);reply[n]=0;return 0;
}
static int wb_vita_copy_file(const char *p,const char *q){
    assert(!strcmp(p,srcpath)&&!strcmp(q,WB_PAYLOAD_NEW));memcpy(copy,input,sizeof copy);
    if(mode==1)copy[sizeof copy-1]^=1; /* corruption after copy, not original input */
    stage_bytes=mode==2?123:sizeof copy;
    return 0;
}
static int readat(const void *ctx,uint64_t off,void *dst,size_t n){
    (void)ctx;assert(off<=stage_bytes&&n<=stage_bytes-off);
    if(mode==3&&off>=4096)return WB_E_IO;
    memcpy(dst,copy+off,n);return WB_OK;
}
static int wb_vita_reader_open(const char *p,wb_reader *r,wb_vfile *f){
    assert(!strcmp(p,WB_PAYLOAD_NEW));r->read_at=readat;r->size=stage_bytes;r->ctx=f;f->live=1;opened++;return 0;
}
static void wb_vita_reader_close(wb_vfile *f){assert(f->live);f->live=0;}
static int sceIoRemove(const char *p){assert(!strcmp(p,WB_PAYLOAD_NEW));++removed;return 0;}
static int wb_vita_payload_swap(const char *p,char *v,size_t cap){
    assert(!strcmp(p,WB_PAYLOAD_NEW)&&cap>=16&&!mode);strcpy(v,"p2.1");swapped++;return 0;
}
#include "deploy.inc"
int main(int argc,char **argv){
    assert(argc==2&&wb_s2_selftest()==WB_OK);FILE *f=fopen(argv[1],"rb");assert(f&&fread(input,1,sizeof input,f)==sizeof input&&fgetc(f)==EOF);fclose(f);
    wb_out out={NULL,emit};
    for(mode=0;mode<4;mode++){
        unsigned n=swapped,r=removed;
        int rc=do_deploy(srcpath,&out,true);
        if(!mode)assert(!rc&&swapped==n+1&&removed==r&&strstr(reply,"OK deploy"));
        else assert(rc<0&&swapped==n&&removed==r+1&&strstr(reply,"ERR payload-not-approved"));
    }
    assert(opened==4);
    puts("PASS terminal deploy: real approved bytes; corrupted protected copy / wrong length / short read rejected without swap; only rejected candidate discarded");
    return 0;
}
