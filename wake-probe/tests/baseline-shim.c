#include "fake.h"
#include "life.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static const char *mode;
static unsigned bg,module,frames,sets,ctrl,reads,store,partial,fdpos,seen,clocks;
static char durable[64],snapshot[64];
static uint32_t framebuffer[1024*544];
static int test(const char *s){return !strcmp(mode,s);}
int sceKernelAllocMemBlock(const char *s,int type,int n,void *arg){
    (void)s;(void)type;(void)arg;assert(n>=1024*544*4);return test("alloc")?-22:3;}
int sceKernelGetMemBlockBase(int id,void **dst){assert(id==3);*dst=framebuffer;return test("map")?-23:0;}
int sceDisplaySetFrameBuf(SceDisplayFrameBuf *p,int sync){
    assert(p->base==framebuffer && sync==1);++sets;return test("submit")?-28:0;}
int sceDisplayWaitSetFrameBuf(void){++frames;return test("wait")?-29:0;}
int sceSysmoduleLoadModule(int id){assert(id==24);++module;return test("bgload")?-27:0;}
int sceCtrlPeekBufferPositive(int port,SceCtrlData *p,int n){
    assert(!port&&n==1);++ctrl;assert(ctrl<8);
    p->timeStamp=test("stamp")&&ctrl==2?1:ctrl+2;p->buttons=ctrl==2?SCE_CTRL_START:0;
    if(test("ctrl0"))return 0;
    return test("ctrl")?-31:1;
}
int sceBgAppUtilStartBgApp(int mode_){(void)mode_;++bg;return 0;}
uint64_t sceKernelGetSystemTimeWide(void){return ++clocks*100001ull;}
int lc_init(void){return test("init")?-21:0;}
int lc_load_arm(lc_arm *a){(void)a;++reads;return (int)UINT32_C(0x80010002);}
int lc_load_trace(lc_trace *t){(void)t;++reads;return (int)UINT32_C(0x80010002);}
int lc_save_arm(const lc_arm *a){(void)a;assert(!"no arm allowed in startup test");return -1;}
int lc_save_trace(const lc_trace *t){(void)t;assert(!"no worker allowed in startup test");return -1;}
int sceIoOpen(const char *s,int m,int unused){assert(!strcmp(s,"savedata0:/lifecycle-startup-rc1.txt")&&m==1&&!unused);
    if(test("read-denied"))return -42;
    fdpos=0;return seen?4:(int)UINT32_C(0x80010002);}
int sceIoRead(int fd,void *out,size_t n){assert(fd==4);
    unsigned avail=(unsigned)sizeof durable-fdpos;
    unsigned k=avail>n?n:avail;if(k>11)k=11;
    memcpy(out,durable+fdpos,k);fdpos+=k;
    if(test("corrupt")&&k){((char*)out)[0]^=1;partial++;}
    return (int)k;}
int sceIoClose(int fd){assert(fd==4);return 0;}
int sceAppUtilSaveDataDataSave(void *p,SceAppUtilSaveDataFile *f,int n,void *slot,SceSize *req){
    assert(!p&&!slot&&req&&n==1&&f->bufSize==64&&!strcmp(f->filePath,"lifecycle-startup-rc1.txt")&&f->mode==0);
    ++store;if(test("save-denied"))return -40;
    memcpy(durable,f->buf,sizeof durable);seen=1;return 0;
}
extern int app_main(void);
int main(int argc,char **argv){
    assert(argc==2);mode=argv[1];if(test("prior")){memset(durable,'?',64);memcpy(snapshot,durable,64);seen=1;}
    int rc=app_main();printf("rc=%d frames=%u submits=%u ctrl=%u bg=%u module=%u reads=%u writes=%u read_corrupt=%u\n",rc,frames,sets,ctrl,bg,module,reads,store,partial);
    if(seen){if(test("prior")){assert(!memcmp(snapshot,durable,64));puts("diag=PRIOR PRESERVED");}
        else printf("diag=%.*s",64,durable);
    }else puts("diag=ABSENT");
    return rc;
}
