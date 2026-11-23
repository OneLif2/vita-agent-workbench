#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wb_panel_keys.h"
#include "wb_panel_cache.h"
static bool visible_fg=true;
static unsigned fg_calls=0;
static bool foreground(bool save){assert(!save);++fg_calls;return visible_fg;}
static wb_panel_keys panel_keys;
static void poll_available(unsigned buttons,uint64_t mono,bool input){
    SceCtrlData pad={0};pad.buttons=buttons;
#include "dispatch.inc"
}
static void poll(unsigned buttons,uint64_t mono){poll_available(buttons,mono,true);}
int main(void){
    const unsigned up=SCE_CTRL_UP,down=SCE_CTRL_DOWN,right=SCE_CTRL_RIGHT;
    wb_mirror_reset();poll(0,0);poll(up,1);assert(!fg_calls);
    wb_mirror_begin();wb_mirror_geometry(140,40);
    char line[150];memset(line,'W',130);memcpy(line+130,"\r\n",2);
    for(int i=0;i<180;i++)wb_mirror_write((const uint8_t*)line,132);
    poll(up,0);assert(!fg_calls);poll(0,1);poll(up,2);
    assert(fg_calls==1&&wb_mirror_browsing()&&wb_mirror_scroll_offset(WB_PANEL_ROWS)==1);
    poll(up,351);assert(fg_calls==1);poll(up,352);assert(fg_calls==2&&wb_mirror_scroll_offset(WB_PANEL_ROWS)==4);
    poll(up,355);assert(fg_calls==2);poll(up,452);assert(fg_calls==3&&wb_mirror_scroll_offset(WB_PANEL_ROWS)==7);
    poll(0,500);poll(right,502);assert(wb_mirror_left(80)==8);
    poll(0,530);poll(down,531);assert(wb_mirror_scroll_offset(WB_PANEL_ROWS)==6);
    poll(0,534);poll(SCE_CTRL_LEFT,535);assert(wb_mirror_left(80)==0);
    poll(0,540);unsigned prior=fg_calls;
    poll(SCE_CTRL_SELECT|SCE_CTRL_SQUARE,543);poll(SCE_CTRL_SQUARE,544);
    assert(prior==fg_calls&&wb_mirror_browsing());
    poll(0,550);poll(SCE_CTRL_SQUARE,551);assert(!wb_mirror_browsing());
    poll(0,600);visible_fg=false;poll(up,601);visible_fg=true;poll(up,990);
    assert(!wb_mirror_browsing());poll(0,991);poll(up,992);assert(wb_mirror_browsing());
    prior=fg_calls;poll_available(up,1000,false);assert(fg_calls==prior);
    poll(up,1001);assert(fg_calls==prior); /* unknown is not a neutral key */
    poll(0,1002);poll(up,1003);assert(fg_calls==prior+1);
    unsigned long long rev=wb_mirror_revision();
    wb_panel_cache caches[2]={{0}};
    for(int b=0;b<2;b++){
        assert(wb_panel_needs_raster(&caches[b],rev,true,"pin","notice"));
        assert(!wb_panel_needs_raster(&caches[b],rev,true,"pin","notice"));
    }
    assert(wb_panel_needs_raster(&caches[0],rev,false,"pin","notice"));
    assert(wb_panel_needs_raster(&caches[0],rev,false,"pin","NEW NOTICE"));
    assert(wb_panel_needs_raster(&caches[0],rev,false,"newpin","NEW NOTICE"));
    wb_mirror_reset();assert(wb_mirror_revision()!=rev);
    assert(wb_panel_needs_raster(&caches[1],wb_mirror_revision(),true,"pin","notice"));
    assert(!wb_mirror_active()&&!wb_mirror_browsing());
    puts("PASS compiled local listener input: neutral/press/hold-repeat/navigation/follow, inactive and background guard, chord isolation, per-buffer raster invalidation.");
}
