/* Only the paired shell can start one immutable game. The VM never receives a
 * file selected by SSH. File contents are identity evidence, not executable input. */
#include "wb_game_vita.h"
#include "wb_game_io.h"
#include "wb_game.h"
#include "wb_sha256.h"
#include <psp2/io/fcntl.h>
#include <psp2/kernel/threadmgr.h>
#include <string.h>
static wb_game_io g;
static SceUID thread=-1;
static uint64_t sequence;
static atomic_uint ended;
static int verify_file(void){
    const int fd=sceIoOpen("ux0:/VITA-POC/tictactoe_ai.py",SCE_O_RDONLY,0);
    if(fd<0)return 0;
    wb_sha256 c;uint8_t chunk[1024],digest[32];char hex[65];size_t n=0;int k;
    wb_sha256_init(&c);
    while((k=sceIoRead(fd,chunk,sizeof chunk))>0){n+=(size_t)k;if(n>14661)break;wb_sha256_update(&c,chunk,(size_t)k);}
    int closed=sceIoClose(fd);if(k!=0||n!=14661||closed<0)return 0;
    wb_sha256_final(&c,digest);wb_sha_hex(digest,sizeof digest,hex);
    return !strcmp(hex,WBG_SCRIPT_SHA)&&!strcmp(hex,WB_GAME_SCRIPT_SHA);
}
static int delay_game(void *ctx,unsigned ms){
    wb_game_io *s=ctx;
    while(ms&&atomic_load(&s->state)==WBG_ACTIVE){unsigned t=ms>20?20:ms;sceKernelDelayThread(t*1000);ms-=t;}
    return atomic_load(&s->state)==WBG_ACTIVE?0:-1;
}
static int read_game(void *ctx,char *p,size_t cap){
    char local[WBG_LINE+1];int k;
    while((k=wbg_readline(ctx,local))==0)sceKernelDelayThread(4000);
    if(k<0)return -1;
    size_t n=strlen(local);if(n>=cap)return -1;memcpy(p,local,n+1);return (int)n;
}
typedef struct {uint8_t carry[3];unsigned used;} utf_state;
static utf_state utf;
static int write_game(void *ctx,const char *p,size_t n){
    /* Runtime may emit one byte at a time. Reassemble UTF-8 hearts before
     * giving the bridge a span; control/invalid bytes are not forwarded. */
    while(n){uint8_t b[512];size_t z=0;
        while(n&&z<sizeof b-3){uint8_t c=(uint8_t)*p++;--n;
            if(utf.used||c>=128){
                static const uint8_t heart[]={0xe2,0x99,0xa5};
                if(c!=heart[utf.used])return -1;
                utf.carry[utf.used++]=c;
                if(utf.used==3){memcpy(b+z,utf.carry,3);z+=3;utf.used=0;}
            }else b[z++]=c;
        }
        if(z){int k;while((k=wbg_write(ctx,b,z))==0)sceKernelDelayThread(4000);if(k<0)return -1;}
    }
    return delay_game(ctx,0);
}
static int work(SceSize sz,void *arg){
    (void)sz;(void)arg;int rc=wb_game_run(&g,read_game,write_game,delay_game);
    if(rc==0&&!utf.used){
        const char end[]="PYTHON exit=0\n";rc=write_game(&g,end,sizeof end-1);
    }
    wbg_finish(&g,rc==0);atomic_store(&ended,1);return 0;
}
const char *wb_gv_start(const char *cwd,bool tty,const char *cmd,const uint8_t *tail,size_t n,int skip_lf,uint64_t *owner){
    if(!owner||*owner||strcmp(cwd,"ux0:/VITA-POC")||strcmp(cmd,WBG_COMMAND))return "ERR cd VITA-POC and run python3 tictactoe_ai.py\n";
    if(thread>=0){
        unsigned t=0;int result=0;
        if(!atomic_load(&ended)||sceKernelWaitThreadEnd(thread,&result,&t)<0||sceKernelDeleteThread(thread)<0)return "ERR game busy\n";
        thread=-1;
    }
    if(!verify_file())return "ERR game file missing or SHA-256 differs\n";
    if(++sequence==0)++sequence;
    wbg_init(&g);atomic_store(&ended,0);memset(&utf,0,sizeof utf);
    if(!wbg_start(&g,sequence,cmd,WB_GAME_SCRIPT_SHA,1,tty)||wbg_prefeed(&g,sequence,tail,n,skip_lf)<0)return "ERR game input refused\n";
    thread=sceKernelCreateThread("wb_game_worker",work,0x10000100,256*1024,0,0,NULL);
    if(thread<0)return "ERR game worker unavailable\n";
    if(sceKernelStartThread(thread,0,NULL)<0){(void)sceKernelDeleteThread(thread);thread=-1;return "ERR game worker start\n";}
    *owner=sequence;return NULL;
}
int wb_gv_tick(uint64_t owner,void *io,int (*rd)(void*,uint8_t*,size_t),int (*wr)(void*,const uint8_t*,size_t)){
    return wbg_tick(&g,owner,1,io,rd,wr);
}
void wb_gv_stop(uint64_t owner){if(owner)wbg_disconnect(&g,owner);}
