#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "active_terminal.h"
enum {W=960,H=544,PITCH=1024};
#include "screen.inc"
#include "wb_screen_mirror.h"
#include "mirror_panel.inc"

static uint32_t pixels[PITCH*H], expected[PITCH*H];
/* Known fake public fingerprint, never use the installed peer identity. */
static const char fixture_pin[]=
    "00000001 00000002 00000003 00000004 00000005 00000006 00000007 00000008";
static void clear_pixels(void) {
    for (int i=0; i<PITCH*H; ++i) pixels[i]=expected[i]=LIVE_TERMINAL_BG;
}
/* Independent 2x raster coordinate oracle. Zero all other pixels including
 * the padding: a residual legacy prompt, cursor or stale hint must fail. */
static void want(int x,int y,const char *s,uint32_t color){
    for(size_t k=0;k<strlen(s);k++){
        if(s[k]==' ')continue;
        const char *pos=strchr(dict,s[k]);assert(pos);
        for(int j=0;j<7;j++)for(int i=0;i<5;i++)if(font[pos-dict][j]&(16u>>i)){
            int off=(y+j*2)*PITCH+x+(int)k*12+i*2;
            assert(x+(int)k*12+i*2+1<W&&y+j*2+1<H);
            expected[off]=expected[off+1]=expected[off+PITCH]=expected[off+PITCH+1]=color;
        }
    }
}
static void check_wait(const char *pin,const char *notice,bool online){
    assert(!wb_mirror_active());clear_pixels();
    draw_mirror(pixels,pin,notice,online);
    want(18,12,"v" WB_BUILD_TAG " - SSH LISTENING",COLOR(120,255,163));
    if(notice&&*notice&&strcmp(notice,LIVE_TERMINAL_CONTROLS))
        want(490,12,notice,LIVE_TERMINAL_FG);
    want(18,37,"VITA AGENT WORKBENCH 2.0",LIVE_TERMINAL_FG);
    want(755,37,online?"AGENT ONLINE":"AGENT READY",LIVE_TERMINAL_FG);
    want(18,105,"AGENT-OPERATED MODE ACTIVE",LIVE_TERMINAL_FG);
    want(18,145,"SSH AND SFTP 192.0.2.10:2222",LIVE_TERMINAL_FG);
    want(18,180,"ZERO-BUTTON UPDATES ENABLED - WBQ2",LIVE_TERMINAL_FG);
    want(18,215,"LIVE CONSOLE MIRRORS HERE WHEN CONNECTED",LIVE_TERMINAL_FG);
    /* 02.18: the host key fingerprint is shown on the PC terminal only; the
     * exact-pixel comparison below fails if any pin text is drawn. */
    want(18,523,"SSH AND TURBO SFTP READY / START EXITS",LIVE_TERMINAL_FG);
    assert(memcmp(expected,pixels,sizeof pixels)==0);
    assert(!wb_mirror_active()&&!wb_mirror_row(0)[0]);
}
#ifdef TEST_CAPTURE
/* Shim only native I/O. The BMP header/pixels are the unchanged production C
 * routine extracted verbatim by the runner (not an independent BMP writer). */
struct Frame{uint32_t *data;};
static struct Frame buf[2];static unsigned cursor=1;
enum {SCE_O_WRONLY=1,SCE_O_CREAT=2,SCE_O_TRUNC=4};
typedef unsigned SceSize;
static FILE *output;
static int sceIoOpen(const char *p,int f,int mode){(void)f;(void)mode;output=fopen(p,"wb");return output?1:-1;}
static int sceIoWrite(int fd,const void *p,SceSize n){assert(fd==1);return (int)fwrite(p,1,n,output);}
static int sceIoSyncByFd(int fd,int flags){assert(fd==1 && !flags);return fflush(output);}
static int sceIoClose(int fd){assert(fd==1);return fclose(output);}
#include "capture.inc"
#endif
int main(void) {
    /* Never let a letter in current or future build tags silently disappear. */
    for(char c='a';c<='z';++c){const char *ch=strchr(dict,c);assert(ch && memchr(font[ch-dict],0xff,7)==NULL);}
    assert(!memcmp(font[strchr(dict,'v')-dict],(uint8_t[]){0,0,17,17,17,10,4},7));
    assert(!memcmp(font[strchr(dict,'>')-dict],(uint8_t[]){16,8,4,2,4,8,16},7));
    clear_pixels();draw(pixels,1,1,"legacy prompt font",LIVE_TERMINAL_FG);
    wb_mirror_reset();check_wait(NULL,NULL,false);
    check_wait(fixture_pin,"R1 AUTHORIZATION REVOKED",false);
    check_wait(fixture_pin,"UPLOAD OK",true); /* authenticated exec, not a shell */
    wb_mirror_write((const uint8_t*)"not authenticated shell output",30);
    check_wait(fixture_pin,NULL,true);
    for(int i=0;i<30;i++)check_wait(fixture_pin,LIVE_TERMINAL_CONTROLS,false);
#ifdef TEST_CAPTURE
    buf[0].data=pixels;assert(display_capture("host-console.bmp")==1);
#endif
    puts("PASS: first ready frame, public host pin, owner notice, exec-only/idle, no WB> or fake prompt; 30 stable frames");
    return 0;
}
