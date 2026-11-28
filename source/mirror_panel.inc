/* One listener presentation; the grid contains only committed shell output.
 * Idle instructions, public fingerprint, and owner notices are local chrome. */
#include "wb_ver.h"
#include <stdio.h>
#include "mirror_font.inc"
#include "wb_font_jetbrains.h"
#include "wb_panel_geometry.h"
#define LIVE_TERMINAL_STATUS "v" WB_BUILD_TAG " - SSH LISTENING"
#define LIVE_TERMINAL_CONTROLS "AGENT MODE READY"
#define LIVE_TERMINAL_GREEN COLOR(120,255,163)
#ifdef WB_SHELL2
#define LIVE_TERMINAL_BG COLOR(13,17,23)
#define LIVE_TERMINAL_FG COLOR(230,237,243)
#else
#define LIVE_TERMINAL_BG COLOR(12,12,12)
#define LIVE_TERMINAL_FG COLOR(204,204,204)
#endif
enum {MIR_X=0,MIR_Y=69,MIR_END=519};
_Static_assert(WB_PANEL_WIDTH_PX==960 && WB_PANEL_BODY_PX==MIR_END-MIR_Y &&
               WB_TYPE_MIN_Y>=1, "local viewport must fit full rows and underline above footer");
_Static_assert((unsigned)WB_JB_WIDTH==WB_TYPE_JB_W && (unsigned)WB_JB_HEIGHT==WB_TYPE_JB_H,
               "JetBrains face and local layout must agree");
/* Leave a gap after the complete build status label. */
enum { LOCAL_NOTICE_X=490 };
_Static_assert(18+12*(sizeof LIVE_TERMINAL_STATUS-1)<LOCAL_NOTICE_X,"status must not overlap local notice");

#ifdef WB_SHELL2
static void mp_rect(uint32_t *p,unsigned x0,unsigned y0,unsigned w,unsigned h,uint32_t c){
    for(unsigned y=y0;y<y0+h&&y<H;y++)
        for(unsigned x=x0;x<x0+w&&x<W;x++)p[y*PITCH+x]=c;
}
static void mp_dot(uint32_t *p,int cx,int cy,int r,uint32_t c){
    for(int dy=-r;dy<=r;dy++)for(int dx=-r;dx<=r;dx++){
        if(dx*dx+dy*dy<=r*r){
            int x=cx+dx,y=cy+dy;
            if(x>=0&&x<W&&y>=0&&y<H)p[(unsigned)y*PITCH+(unsigned)x]=c;
        }
    }
}
static void mp_str(uint32_t *p,unsigned x,unsigned y,unsigned scale,const char *s,uint32_t c){
    for(;*s;s++,x+=6*scale){
        if(x+5*scale>W)break;
        if(*s==' ')continue;
        const uint8_t *g=mirror_glyph(*s);
        if(!g)continue;
        for(unsigned j=0;j<7;j++)for(unsigned i=0;i<5;i++)if(g[j]&(1u<<(4-i))){
            uint32_t *px=p+(y+j*scale)*PITCH+x+i*scale;
            px[0]=c;
            if(scale>=2)px[1]=px[PITCH]=px[PITCH+1]=c;
        }
    }
}
static uint32_t mp_ansi_color(uint8_t idx){
    static const uint32_t pal[16]={
        COLOR(230,237,243), /* 0: default soft white */
        COLOR(248,81,73),   /* 1: red */
        COLOR(63,185,80),   /* 2: green */
        COLOR(210,153,34),  /* 3: yellow */
        COLOR(88,166,255),  /* 4: blue */
        COLOR(188,140,255), /* 5: magenta */
        COLOR(57,197,207),  /* 6: cyan */
        COLOR(201,209,217), /* 7: light gray */
        COLOR(139,148,158), /* 8: bright black / muted */
        COLOR(255,123,114), /* 9: bright red */
        COLOR(86,211,100),  /* 10: bright green */
        COLOR(227,179,65),  /* 11: bright yellow */
        COLOR(121,192,255), /* 12: bright blue */
        COLOR(210,168,255), /* 13: bright magenta */
        COLOR(86,212,221),  /* 14: bright cyan */
        COLOR(255,255,255)  /* 15: bright white */
    };
    return pal[idx&15u];
}
static uint32_t mp_row_tint(const char *s,size_t len){
    if(len>=4 && (!strncmp(s,"ERR ",4) || !strncmp(s,"TTY1 ERR",8)))return COLOR(255,123,114);
    if(len>=3 && (!strncmp(s,"OK ",3) || !strncmp(s,"TTY1 OK",7)))return COLOR(86,211,100);
    if(len>=2 && s[len-1]=='/' && (s[0]=='d' || !strchr(s,' ')))return COLOR(121,192,255);
    return LIVE_TERMINAL_FG;
}
static void draw_mirror(uint32_t *p,const char *host_pin,const char *event,bool agent_online){
    (void)host_pin; /* Host key is verified and displayed on the PC terminal only. */
    const uint32_t bar_bg=COLOR(22,27,34);
    const uint32_t border=COLOR(48,54,61);
    const uint32_t muted=COLOR(139,148,158);
    const uint32_t accent_green=COLOR(86,211,100);
    const uint32_t accent_blue=COLOR(121,192,255);
    const uint32_t accent_cyan=COLOR(86,212,221);
    const wb_type_style style=wb_type_get();
    const unsigned scale=style.scale,cw=wb_type_cell_w(style),ch=wb_type_cell_h(style);
    const unsigned gw=wb_type_glyph_w(style),gh=wb_type_glyph_h(style);
    const unsigned vc=wb_type_cols(style),vr=wb_type_rows(style);

    /* Top computer-terminal window titlebar */
    mp_rect(p,0,0,W,34,bar_bg);
    mp_rect(p,0,34,W,1,border);
    mp_dot(p,20,17,6,COLOR(255,95,86));
    mp_dot(p,40,17,6,COLOR(255,189,46));
    mp_dot(p,60,17,6,COLOR(39,201,63));
    mp_str(p,82,10,2,"pi@vita - Linux Terminal (v" WB_VERSION ")",LIVE_TERMINAL_FG);
    /* Right status pill */
    mp_rect(p,778,5,168,24,agent_online?COLOR(25,75,45):COLOR(33,38,45));
    mp_dot(p,794,17,4,agent_online?accent_green:accent_cyan);
    mp_str(p,808,10,2,agent_online?"SSH ONLINE":"READY:2222",agent_online?accent_green:accent_cyan);

    /* Sub-header telemetry bar */
    mp_rect(p,0,35,W,28,COLOR(16,21,28));
    mp_rect(p,0,63,W,1,COLOR(33,38,45));
    mp_str(p,14,42,2,"192.0.2.10:2222",muted);
    if(wb_mirror_active()){
        const unsigned left=wb_mirror_left(vc);
        char mark[48];
        if(wb_mirror_browsing())snprintf(mark,sizeof mark,"HIST -%u COL %u",wb_mirror_scroll_offset(vr),left+1);
        else snprintf(mark,sizeof mark,"LIVE %ux%u COL %u",vc,vr,left+1);
        mp_str(p,264,42,2,mark,wb_mirror_browsing()?COLOR(227,179,65):accent_green);
    }else{
        mp_str(p,264,42,2,"SSH + TURBO SFTP / WBQ2",accent_blue);
    }
    if(event && *event && strcmp(event,LIVE_TERMINAL_CONTROLS))
        mp_str(p,580,42,2,event,COLOR(227,179,65));
    else
        mp_str(p,648,42,2,"AGENT-OPERATED 2.0",muted);

    /* Bottom terminal status bar */
    mp_rect(p,0,519,W,1,border);
    mp_rect(p,0,520,W,24,bar_bg);
    mp_rect(p,8,523,62,18,COLOR(35,134,54));
    mp_str(p,15,525,2,"BASH",COLOR(255,255,255));
    mp_str(p,80,525,2,wb_mirror_active()?
        "DPAD:Scroll/Pan  SQUARE:Live  START:Exit":
        "SSH/SFTP Ready  Zero-Button WBQ2  START:Exit",muted);
    mp_str(p,746,525,2,"v" WB_BUILD_TAG,muted);

    if(!wb_mirror_active()){
        mp_str(p,18,86,2,"Vita Linux Terminal " WB_VERSION " (ARMv7 Cortex-A9 / Workbench 2.0)",accent_cyan);
        mp_str(p,18,120,2," * SSH / PTY  : ssh pi@192.0.2.10 -p 2222",LIVE_TERMINAL_FG);
        mp_str(p,18,148,2," * Turbo SFTP : active (0-100% progress + SHA-256 verify)",LIVE_TERMINAL_FG);
        mp_str(p,18,176,2," * Filesystem : /ux0  /ur0  /uma0  /inbox (writable)",LIVE_TERMINAL_FG);
        mp_str(p,18,204,2," * Core Update: zero-button WBQ2 + INAP00019 auto-return",LIVE_TERMINAL_FG);
        mp_str(p,18,242,2,"Last login: awaiting paired SSH session...",muted);
        mp_str(p,18,284,2,"pi@vita",accent_green);
        mp_str(p,102,284,2,":",LIVE_TERMINAL_FG);
        mp_str(p,114,284,2,"/ux0",accent_blue);
        mp_str(p,162,284,2,"$ ",LIVE_TERMINAL_FG);
        mp_rect(p,186,284,10,14,accent_green);
        return;
    }
    const unsigned cols=wb_mirror_cols(),cy=wb_mirror_cursor_row();
    const unsigned cc=wb_mirror_cursor_col()<cols?wb_mirror_cursor_col():cols-1;
    const unsigned left=wb_mirror_left(vc),top=cy<vr?0:cy+1-vr;
    const bool browsing=wb_mirror_browsing();
    const bool show_cursor=agent_online && !browsing && cc>=left && cc-left<vc;
    const unsigned cur_row=cy-top,cur_col=cc-left;
    if(show_cursor)mp_rect(p,MIR_X+cur_col*cw,MIR_Y+cur_row*ch,gw*scale,gh*scale,accent_green);
    for(unsigned r=0;r<vr;r++){
        const char *s=wb_mirror_view_row(r,vr);size_t len=strlen(s);
        const uint8_t *fg_row=wb_mirror_view_fg(r,vr);
        const uint32_t row_default=mp_row_tint(s,len);
        for(unsigned c=0;c<vc&&left+c<len;c++){
            if(s[left+c]==' ')continue;
            const uint8_t *glyph=style.family==WB_TYPE_JETBRAINS?
                wb_jb_glyph((unsigned char)s[left+c]):mirror_glyph(s[left+c]);
            if(!glyph)continue;
            const bool on_cur=show_cursor && r==cur_row && c==cur_col;
            const uint8_t attr=fg_row?fg_row[left+c]:0;
            const uint32_t color=on_cur?LIVE_TERMINAL_BG:(attr?mp_ansi_color(attr):row_default);
            const unsigned x=MIR_X+c*cw,y=MIR_Y+r*ch;
            for(unsigned j=0;j<gh;j++)for(unsigned i=0;i<gw;i++)if(glyph[j]&(1u<<(gw-1-i))){
                uint32_t *px=p+(y+j*scale)*PITCH+x+i*scale;px[0]=color;
                if(scale>=2)px[1]=px[PITCH]=px[PITCH+1]=color;
                if(scale==3)px[2]=px[PITCH+2]=px[2*PITCH]=px[2*PITCH+1]=px[2*PITCH+2]=color;
            }
        }
    }
}
#else
static void draw_mirror(uint32_t *p,const char *host_pin,const char *event,bool agent_online){
    (void)host_pin; /* Host key is verified and displayed on the PC terminal only. */
    draw_at(p,18,12,2,LIVE_TERMINAL_STATUS,LIVE_TERMINAL_GREEN);
    if(event && *event && strcmp(event,LIVE_TERMINAL_CONTROLS))
        draw_at(p,LOCAL_NOTICE_X,12,2,event,LIVE_TERMINAL_FG);
    draw_at(p,18,37,2,"VITA AGENT WORKBENCH 2.0",LIVE_TERMINAL_FG);
    draw_at(p,755,37,2,agent_online?"AGENT ONLINE":"AGENT READY",LIVE_TERMINAL_FG);
    draw_at(p,18,523,2,wb_mirror_active()?
        "DPAD SCROLL/PAN / SQUARE LIVE / START EXITS":
        "SSH AND TURBO SFTP READY / " TERMINAL_EXIT,LIVE_TERMINAL_FG);
    if(!wb_mirror_active()){
        draw_at(p,18,105,2,"AGENT-OPERATED MODE ACTIVE",LIVE_TERMINAL_FG);
        draw_at(p,18,145,2,"SSH AND SFTP 192.0.2.10:2222",LIVE_TERMINAL_FG);
        draw_at(p,18,180,2,"ZERO-BUTTON UPDATES ENABLED - WBQ2",LIVE_TERMINAL_FG);
        draw_at(p,18,215,2,"LIVE CONSOLE MIRRORS HERE WHEN CONNECTED",LIVE_TERMINAL_FG);
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
#endif
