#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include "startup.h"
#define DIR "ux0:data/INAP00018"
#define PRIMARY DIR "/startup.log"
#define SECONDARY "ux0:VITA-POC/ina_vita_workbench_v031_startup.log"
static const char *chosen;
static unsigned records;

void startup_mark(const char *stage,int32_t rc) {
    if(records>=100)return;
    const int flags=SCE_O_WRONLY|SCE_O_CREAT|(records?SCE_O_APPEND:SCE_O_TRUNC);
    if(!records)sceIoMkdir(DIR,0700);
    int d=sceIoOpen(chosen?chosen:PRIMARY,flags,0600);
    if(d<0&&!chosen){
        d=sceIoOpen(SECONDARY,flags,0600);
        if(d>=0)chosen=SECONDARY;
    }
    if(d<0)return;
    if(!chosen)chosen=PRIMARY;
    char line[52];
    unsigned n=0;
    while(n<40&&stage[n]){line[n]=stage[n];n++;}
    line[n++]=' ';line[n++]='0';line[n++]='x';
    const uint32_t bits=(uint32_t)rc;
    const char hex[]="0123456789ABCDEF";
    for(unsigned k=0;k<8;k++)line[n++]=hex[(bits>>(28-4*k))&15u];
    line[n++]='\n';
    if(sceIoWrite(d,line,n)==(int)n)records++;
    (void)sceIoSyncByFd(d,0);
    (void)sceIoClose(d);
}
static void first(void){startup_mark("PREINIT ENTER",0);}
__attribute__((used,section(".preinit_array")))
static void (*const preinit)(void)=first;
/* SDK pte init is priority 101 in the audited map. Prove it returned when possible. */
__attribute__((constructor(102)))
static void after_pthread(void){startup_mark("AFTER PTHREAD CTOR",0);}
