/* One listener presentation; the grid contains only committed shell output.
 * Idle instructions, public fingerprint, and owner notices are local chrome. */
#include "wb_ver.h"
#include <stdio.h>
#include "mirror_font.inc"
#include "wb_font_jetbrains.h"
#include "wb_panel_geometry.h"
#define LIVE_TERMINAL_STATUS "v" WB_BUILD_TAG " - SSH LISTENING"
#define LIVE_TERMINAL_CONTROLS "TRIANGLE REVIEW UPDATE / SELECT REVOKES"
#define LIVE_TERMINAL_GREEN COLOR(120,255,163)
#define LIVE_TERMINAL_BG COLOR(12,12,12)
#define LIVE_TERMINAL_FG COLOR(204,204,204)
enum {MIR_X=0,MIR_Y=69,MIR_END=519};
_Static_assert(WB_PANEL_WIDTH_PX==960 && WB_PANEL_BODY_PX==MIR_END-MIR_Y &&
               WB_TYPE_MIN_Y>=1, "local viewport must fit full rows and underline above footer");
_Static_assert((unsigned)WB_JB_WIDTH==WB_TYPE_JB_W && (unsigned)WB_JB_HEIGHT==WB_TYPE_JB_H,
               "JetBrains face and local layout must agree");
/* Leave a gap after the complete 01.81 digestcheck build label. */
enum { LOCAL_NOTICE_X=490 };
_Static_assert(18+12*(sizeof LIVE_TERMINAL_STATUS-1)<LOCAL_NOTICE_X,"status must not overlap local notice");
static void draw_mirror(uint32_t *p,const char *host_pin,const char *event,bool agent_online){
    draw_at(p,18,12,2,LIVE_TERMINAL_STATUS,LIVE_TERMINAL_GREEN);
    if(event && *event && strcmp(event,LIVE_TERMINAL_CONTROLS))
        draw_at(p,LOCAL_NOTICE_X,12,2,event,LIVE_TERMINAL_FG);
    draw_at(p,18,37,2,"VITA AGENT TERMINAL / SHARED SSH",LIVE_TERMINAL_FG);
    draw_at(p,755,37,2,agent_online?"AGENT ONLINE":"AGENT IDLE",LIVE_TERMINAL_FG);
    draw_at(p,18,523,2,wb_mirror_active()?
        "DPAD SCROLL/PAN / SQUARE LIVE / TRIANGLE REVIEW / SELECT REVOKES / START EXITS":
        LIVE_TERMINAL_CONTROLS " / " TERMINAL_EXIT,LIVE_TERMINAL_FG);
    if(!wb_mirror_active()){
        /* Initial policy/auth controls are unchanged. An authenticated exec
         * or SFTP connection does not create an interactive prompt or grid. */
        draw_at(p,18,95,2,"WAITING FOR INTERACTIVE SSH",LIVE_TERMINAL_FG);
        if(host_pin && *host_pin){
            draw_at(p,18,145,2,"SSH HOST KEY SHA256 HEX",LIVE_TERMINAL_FG);
            draw_at(p,18,172,2,host_pin,LIVE_TERMINAL_FG);
        }
        return;
    }
    /* PTY geometry describes the remote grid, never the local type size. */
    const wb_type_style style=wb_type_get();
    const unsigned scale=style.scale,cw=wb_type_cell_w(style),ch=wb_type_cell_h(style);
    const unsigned gw=wb_type_glyph_w(style),gh=wb_type_glyph_h(style);
    const unsigned vc=wb_type_cols(style),vr=wb_type_rows(style);
    const unsigned cols=wb_mirror_cols(), cy=wb_mirror_cursor_row();
    const unsigned cc=wb_mirror_cursor_col()<cols?wb_mirror_cursor_col():cols-1;
    const unsigned left=wb_mirror_left(vc),top=cy<vr?0:cy+1-vr;
    const bool browsing=wb_mirror_browsing();
    char mark[32];
    if(browsing)snprintf(mark,sizeof mark,"HISTORY -%u COL %u",wb_mirror_scroll_offset(vr),left+1);
    else snprintf(mark,sizeof mark,"LIVE COL %u",left+1);
    draw_at(p,475,37,2,mark,LIVE_TERMINAL_GREEN);
    for(unsigned r=0;r<vr;r++){
        const char *s=wb_mirror_view_row(r,vr);size_t len=strlen(s);
        for(unsigned c=0;c<vc&&left+c<len;c++){
            if(s[left+c]==' ')continue;
            const uint8_t *glyph=style.family==WB_TYPE_JETBRAINS?
                wb_jb_glyph((unsigned char)s[left+c]):mirror_glyph(s[left+c]);
            if(!glyph)continue;
            const unsigned x=MIR_X+c*cw,y=MIR_Y+r*ch;
            for(unsigned j=0;j<gh;j++)for(unsigned i=0;i<gw;i++)if(glyph[j]&(1u<<(gw-1-i))){
                uint32_t *px=p+(y+j*scale)*PITCH+x+i*scale;px[0]=LIVE_TERMINAL_FG;
                if(scale>=2)px[1]=px[PITCH]=px[PITCH+1]=LIVE_TERMINAL_FG;
                if(scale==3)px[2]=px[PITCH+2]=px[2*PITCH]=px[2*PITCH+1]=px[2*PITCH+2]=LIVE_TERMINAL_FG;
            }
        }
    }
    if(agent_online && !browsing && cc>=left && cc-left<vc){
        const unsigned x=MIR_X+(cc-left)*cw,y=MIR_Y+(cy-top)*ch+gh*scale;
        for(unsigned i=0;i<gw*scale;i++)p[y*PITCH+x+i]=LIVE_TERMINAL_FG;
    }
}
