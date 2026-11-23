/* Independent physical pixel-oracle for Vita's compiled renderer. No display
 * change, drawing calls, or unit conversion delegated to the host OS. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_screen_mirror.h"
#include "active_terminal.h"
#include "wb_panel_keys.h"
#include "wb_panel_cache.h"
enum { W=960,H=544,PITCH=1024 };
#include "screen.inc"
#include "mirror_panel.inc"
static uint32_t fb[H*PITCH], reference[H*PITCH];
static void print_text(const char *s){wb_mirror_write((const uint8_t*)s,strlen(s));}
static void frame(void){
    for(unsigned i=0;i<H*PITCH;++i)fb[i]=LIVE_TERMINAL_BG;
    draw_mirror(fb,NULL,NULL,true);
}
static bool same(wb_type_style a,wb_type_style b){
    return a.family==b.family&&a.scale==b.scale&&a.gap_x==b.gap_x&&a.gap_y==b.gap_y;
}
static void unchanged_shell(void){
    assert(wb_mirror_cols()==132&&wb_mirror_rows()==40);
    assert(wb_mirror_cursor_col()==2&&wb_mirror_cursor_row()==1);
    assert(!strcmp(wb_mirror_row(0),"HH")&&!strcmp(wb_mirror_row(1),"HH"));
}
static void check(wb_type_style s){
    uint64_t re=wb_mirror_revision();bool change=!same(wb_type_get(),s);
    assert(wb_type_set(s)&&same(wb_type_get(),s)&&wb_mirror_revision()==re+(unsigned)change);
    assert(wb_type_set(s)&&wb_mirror_revision()==re+(unsigned)change);
    unchanged_shell();frame();
    unsigned w=s.family?8:5,h=s.family?14:7;
    unsigned cw=w*s.scale+s.gap_x,ch=h*s.scale+s.gap_y;
    assert(WB_PANEL_COLS==960/cw&&WB_PANEL_ROWS==450/ch);
    const uint8_t *g=s.family?wb_jb_glyph('H'):mirror_glyph('H');
    for(unsigned y=69;y<519;y++)for(unsigned x=0;x<PITCH;x++){
        unsigned yy=y-69,col=x/cw,row=yy/ch,px=x%cw,py=yy%ch;
        bool stroke=col<2&&row<2&&px<w*s.scale&&py<h*s.scale&&
                    (g[py/s.scale]&(1u<<(w-1-px/s.scale)));
        bool caret=col==2&&row==1&&py==h*s.scale&&px<w*s.scale;
        assert(fb[y*PITCH+x]==(stroke||caret?LIVE_TERMINAL_FG:LIVE_TERMINAL_BG));
    }
    assert(!memcmp(fb,reference,69*PITCH*sizeof *fb));
    assert(!memcmp(fb+519*PITCH,reference+519*PITCH,(H-519)*PITCH*sizeof *fb));
}
static void pad_and_cache(void){
    wb_panel_cache caches[2]={0};assert(wb_type_set(WB_TYPE_DEFAULT));
    wb_mirror_begin();wb_mirror_geometry(132,40);
    char row[128];memset(row,'q',100);row[100]=0;
    for(unsigned i=0;i<74;i++){char prefix[8];snprintf(prefix,sizeof prefix,"%03u",i);print_text(prefix);print_text(row);print_text("\r\n");}
    for(unsigned i=0;i<2;i++)assert(wb_panel_needs_raster(&caches[i],wb_mirror_revision(),true,"pin",""));
    wb_type_style narrow={1,3,4,10};
    assert(wb_type_set(narrow)&&WB_PANEL_COLS==34&&WB_PANEL_ROWS==8);
    for(unsigned i=0;i<2;i++){
        assert(wb_panel_needs_raster(&caches[i],wb_mirror_revision(),true,"pin",""));
        assert(!wb_panel_needs_raster(&caches[i],wb_mirror_revision(),true,"pin",""));
    }
    wb_panel_apply(SCE_CTRL_UP,false);assert(wb_mirror_browsing());
    assert(!strncmp(wb_mirror_view_row(0,8),"066",3));
    wb_panel_apply(SCE_CTRL_RIGHT,false);assert(wb_mirror_left(34)==8);
    for(unsigned i=0;i<30;i++)wb_panel_apply(SCE_CTRL_RIGHT,false);
    assert(wb_mirror_left(34)==98); /* Actual 132 columns minus 34, not old 80. */
    wb_panel_apply(SCE_CTRL_SQUARE,false);
    assert(!wb_mirror_browsing()&&wb_mirror_cols()==132&&wb_mirror_rows()==40);
    /* Enormous metric inputs must not overflow arithmetic, touch a byte or dirty caches. */
    const wb_type_style bad[]={{2,2,2,6},{0,0,2,6},{0,4,2,6},{1,2,5,6},{1,2,2,1},{0,2,2,11},{~0u,~0u,~0u,~0u}};
    uint64_t rev=wb_mirror_revision();
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){
        assert(!wb_type_set(bad[i])&&wb_mirror_revision()==rev&&same(wb_type_get(),narrow));
        assert(wb_type_rows(bad[i])==22&&wb_type_cols(bad[i])==80);
    }
}
static void preview(const char *path,wb_type_style s){
    wb_mirror_begin();wb_mirror_geometry(132,40);assert(wb_type_set(s));
    print_text("ux0:/> ver\r\nVita Agent Workbench 01.70\r\n\r\nux0:/> pwd\r\nux0:/\r\n\r\n");
    print_text("ux0:/> ls -l\r\nd  data/\r\nd  VITA-POC/\r\n\r\n");
    print_text("Readable?  0O  1Il  5S  []{}  plain_text.py\r\n\r\nux0:/> ");
    frame();FILE *f=fopen(path,"wb");assert(f);
    for(unsigned y=0;y<H;y++)for(unsigned x=0;x<W;x++){
        uint32_t p=fb[y*PITCH+x];unsigned char rgb[]={(unsigned char)p,(unsigned char)(p>>8),(unsigned char)(p>>16)};
        assert(fwrite(rgb,1,3,f)==3);
    }
    assert(!fclose(f));
}
int main(int argc,char **argv){
    draw(fb,1,1,"fixture",0);wb_mirror_begin();wb_mirror_geometry(132,40);
    assert(same(wb_type_get(),WB_TYPE_DEFAULT));print_text("HH\r\nHH");frame();memcpy(reference,fb,sizeof fb);
    unsigned profiles=0;
    for(unsigned f=0;f<=1;f++)for(unsigned n=1;n<=3;n++)
    for(unsigned x=0;x<=4;x++)for(unsigned y=2;y<=10;y++){check((wb_type_style){f,n,x,y});++profiles;}
    pad_and_cache();
    if(argc==3){preview(argv[1],WB_TYPE_DEFAULT);preview(argv[2],(wb_type_style){1,1,2,6});}
    printf("PASS: %u actual framebuffer profiles, exact pitch/glyphs/cursor; header, footer, padding unchanged; dynamic navigation and cache; rejected bad values preserve style and PTY\n",profiles);
    return 0;
}
