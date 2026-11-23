#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_screen_mirror.h"
#include "active_terminal.h"
enum { W=960,H=544,PITCH=1024 };
#include "screen.inc"
#include "mirror_panel.inc"
static uint32_t fb[H*PITCH],before[H*PITCH];
/* Capture with real production display_capture; replace only Vita file IO. */
struct Frame{uint32_t *data;};static struct Frame buf[2];static unsigned cursor=1;
enum {SCE_O_WRONLY=1,SCE_O_CREAT=2,SCE_O_TRUNC=4};typedef unsigned SceSize;
static FILE *output;
static int sceIoOpen(const char*p,int flags,int mode){(void)flags;(void)mode;output=fopen(p,"wb");return output?1:-1;}
static int sceIoWrite(int fd,const void*p,SceSize n){assert(fd==1);return (int)fwrite(p,1,n,output);}
static int sceIoSyncByFd(int fd,int flags){assert(fd==1&&!flags);return fflush(output);}
static int sceIoClose(int fd){assert(fd==1);return fclose(output);}
#include "capture.inc"
static void writeb(const char *s){wb_mirror_write((const uint8_t *)s,strlen(s));}
static void frame(bool online){
    for(size_t i=0;i<H*PITCH;i++)fb[i]=LIVE_TERMINAL_BG;
    draw_mirror(fb,NULL,NULL,online);
}
static void unit(void){
    wb_mirror_reset();writeb("never activate via arbitrary bytes");assert(!wb_mirror_active());
    wb_mirror_begin();assert(wb_mirror_active()&&!wb_mirror_row(0)[0]);
    writeb("ux0:/> abc\b \bd\r\n");assert(!strcmp(wb_mirror_row(0),"ux0:/> abd"));assert(wb_mirror_cursor_row()==1);
    writeb("a");writeb("\342");writeb("\231");writeb("\245G");assert(!strcmp(wb_mirror_row(1),"a\177G"));
    writeb("\033[2J");writeb("\033]title");writeb("\aX");assert(!strcmp(wb_mirror_row(1),"a\177GX"));
    writeb("\rY");assert(!strcmp(wb_mirror_row(1),"Y\177GX"));
    wb_mirror_begin();for(int i=0;i<WB_MIRROR_COLS;i++)writeb("w");
    assert(wb_mirror_cursor_col()==WB_MIRROR_COLS&&wb_mirror_cursor_row()==0);
    writeb("q");assert(wb_mirror_cursor_col()==1&&!strcmp(wb_mirror_row(1),"q"));
    wb_mirror_begin();for(int i=0;i<WB_MIRROR_COLS;i++)writeb("w");
    writeb("\r\nx");assert(wb_mirror_cursor_row()==1);
    wb_mirror_begin();for(int i=0;i<1000;i++){char row[22];snprintf(row,sizeof row,"%d\r\n",i);writeb(row);}
    assert(!strcmp(wb_mirror_row(0),"977")&&!strcmp(wb_mirror_row(22),"999")&&!wb_mirror_row(23)[0]&&!wb_mirror_row(900)[0]);
    wb_mirror_begin();writeb("tab\to");assert(!strcmp(wb_mirror_row(0),"tab     o"));
    wb_mirror_begin();wb_mirror_geometry(7,3);writeb("0123456789\r\nabcd");
    assert(!strcmp(wb_mirror_row(0),"0123456")&&!strcmp(wb_mirror_row(1),"789"));
    wb_mirror_geometry(14,5);assert(!strcmp(wb_mirror_row(0),"0123456789")&&!strcmp(wb_mirror_row(1),"abcd"));
    assert(wb_mirror_cursor_col()==4&&wb_mirror_cursor_row()==1);
    wb_mirror_geometry(4,3);assert(!strcmp(wb_mirror_row(0),"4567")&&!strcmp(wb_mirror_row(1),"89"));
    assert(!strcmp(wb_mirror_row(2),"abcd")&&wb_mirror_cursor_col()==4);
    wb_mirror_geometry(65000,900);assert(wb_mirror_cols()==512&&wb_mirror_rows()==128);
    wb_mirror_begin();assert(wb_mirror_cols()==80&&wb_mirror_rows()==24&&!wb_mirror_row(0)[0]);
    writeb("abc\nZ");assert(!strcmp(wb_mirror_row(1),"   Z"));
    wb_mirror_begin();writeb("ux0:/> pwf\b \bd");assert(!strcmp(wb_mirror_row(0),"ux0:/> pwd")&&wb_mirror_cursor_col()==10);
    wb_mirror_reset();assert(!wb_mirror_active());for(int i=0;i<WB_MIRROR_ROWS;i++)assert(!wb_mirror_row((unsigned)i)[0]);
}
int main(int argc,char **argv){
    assert(argc==5||argc==7);draw(fb,1,1,"legacy",LIVE_TERMINAL_FG);unit();wb_mirror_begin();wb_mirror_geometry((unsigned)atoi(argv[3]),(unsigned)atoi(argv[4]));FILE *s=fopen(argv[1],"rb");assert(s);
    int c;while((c=fgetc(s))!=EOF){uint8_t b=(uint8_t)c;wb_mirror_write(&b,1);}assert(!ferror(s));fclose(s);
    if(argc==7){(void)wb_mirror_scroll(atoi(argv[5]),WB_PANEL_ROWS);(void)wb_mirror_pan(atoi(argv[6]),WB_PANEL_COLS);}
    frame(true);memcpy(before,fb,sizeof fb);frame(false);
    /* One cursor underline only in live mode; never draw it into another
     * row's spacing or onto the footer. This is an independent pixel oracle. */
    unsigned vr=wb_mirror_rows()<22?wb_mirror_rows():22,cy=wb_mirror_cursor_row();
    unsigned last_live=cy<vr?cy:vr-1,cc=wb_mirror_cursor_col(),cols=wb_mirror_cols();
    if(cc>=cols)cc=cols-1;
    unsigned left=wb_mirror_left(80),ink=0;
    for(unsigned y=69;y<523;y++)for(unsigned x=0;x<W;x++){
        bool cursor=!wb_mirror_browsing()&&cc>=left&&cc-left<80&&
            y==69+last_live*20+14&&x>=(cc-left)*12&&x<(cc-left)*12+10;
        if(cursor){assert(before[y*PITCH+x]==LIVE_TERMINAL_FG&&fb[y*PITCH+x]==LIVE_TERMINAL_BG);++ink;}
        else assert(before[y*PITCH+x]==fb[y*PITCH+x]);
        if(y>=69+22*20||(y-69)%20>=14)assert(fb[y*PITCH+x]==LIVE_TERMINAL_BG);
    }
    assert(ink==(wb_mirror_browsing()?0u:10u));
    for(unsigned y=MIR_Y;y<MIR_END;y++)for(unsigned x=0;x<PITCH;x++){
        if(x>=W)assert(fb[y*PITCH+x]==LIVE_TERMINAL_BG);
    }
    buf[0].data=fb;assert(display_capture(argv[2]));return 0;
}
