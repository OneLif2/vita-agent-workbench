/* Offline framebuffer probe for two versions: identical PTY input, geometry
 * and local request to see 96 older visual rows. Observe real framebuffer
 * pixels, not renderer constants or a version -> expected lookup. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_screen_mirror.h"
#include "active_terminal.h"
enum {W=960,H=544,PITCH=1024};
#include "screen.inc"
#include "mirror_panel.inc"
static uint32_t pixels[H*PITCH];
static void frame(void){
    for(unsigned i=0;i<H*PITCH;i++)pixels[i]=LIVE_TERMINAL_BG;
    draw_mirror(pixels,NULL,NULL,false);
}
/* Compare the leftmost whole cell with actual glyph strokes, not line metadata. */
static bool glyph_at(unsigned top,unsigned scale,char c){
    const uint8_t *g=mirror_glyph(c);
    if(!g)return false;
    for(unsigned y=0;y<9*scale;y++)for(unsigned x=0;x<6*scale;x++){
        bool lit=y/scale<7 && x/scale<5 && (g[y/scale]&(16u>>(x/scale)));
        if(pixels[(top+y)*PITCH+x]!=(lit?LIVE_TERMINAL_FG:LIVE_TERMINAL_BG))return false;
    }
    return true;
}
static bool matches(unsigned scale,char c){return glyph_at(69,scale,c);}
static void bytes(const char *s){wb_mirror_write((const uint8_t *)s,strlen(s));}
int main(void){
    /* Use same real production glyph drawing helper in both compilations. */
    draw(pixels,1,1,"fixture",LIVE_TERMINAL_FG);
    wb_mirror_begin();wb_mirror_geometry(132,40);
    bytes("H");frame();
    unsigned scale=matches(2,'H')?2:matches(1,'H')?1:0;
    if(!scale){fputs("unrecognized first glyph pixels\n",stderr);return 1;}
    /* Find a second H on the bitmap; measure stride without using geometry
     * constants. Restart fixture before the shared 70-line history trial. */
    bytes("\r\nH");frame();unsigned pitch=0,hits=0;
    for(unsigned dy=1;dy<=32;dy++)if(glyph_at(69+dy,scale,'H')){pitch=dy;hits++;}
    if(hits!=1){fputs("ambiguous physical row stride\n",stderr);return 1;}
    wb_mirror_begin();wb_mirror_geometry(132,40);bytes("H");
    /* Ensure the original H is outside both live grids; every filler row begins X. */
    for(int i=0;i<70;i++)bytes("\r\nX");
    frame();
    int was_first=matches(scale,'H'), changed=0;
#if HAS_NAV_API
    (void)wb_mirror_scroll(96,WB_PANEL_ROWS);
    changed=1;
#endif
    frame();
    int old_seen=matches(scale,'H');
    printf("{\"pty\":[132,40],\"first_glyph\":\"H\",\"filler_rows\":70,"
           "\"older_requested\":96,\"glyph_scale\":%u,\"body_glyph_width\":%u,"
           "\"body_glyph_height\":%u,\"row_pitch_px\":%u,\"at_live_H_before_request\":%d,"
           "\"scroll_entry_available\":%d,\"at_top_H_after_request\":%d}\n",
           scale,scale*5,scale*7,pitch,was_first,changed,old_seen);
    return 0;
}
