#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <psp2/gxm.h>
#include <psp2/display.h>
#include <psp2/common_dialog.h>
#include <psp2/apputil.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/sysmem.h>
#include "display.h"
#include "active_terminal.h"
#include "startup.h"
#include "dialog_options.h"
#include <psp2/kernel/threadmgr.h>
enum {W=960,H=544,PITCH=1024,FB_BYTES=9*256*1024};
#include "screen.inc"
#include "wb_screen_mirror.h"
#include "mirror_panel.inc"
#include "wb_xfer_panel.inc"
#include "wb_panel_cache.h"
static struct Frame {
    void *data;
    SceGxmColorSurface surface;
    SceGxmSyncObject *sync;
    SceUID id;
    bool mapped;
    wb_panel_cache mirror_cache;
    wb_xfer_ui meter;
} buf[2]={{.id=-1},{.id=-1}};
static unsigned cursor=1;
static bool gxm,app_util;
static void show(const void *p) {
    SceDisplayFrameBuf frame={.size=sizeof frame,.base=*(void *const *)p,.pitch=PITCH,
        .pixelformat=SCE_DISPLAY_PIXELFORMAT_A8B8G8R8,.width=W,.height=H};
    sceDisplaySetFrameBuf(&frame,SCE_DISPLAY_SETBUF_NEXTFRAME);
}
int display_init(void) {
    SceAppUtilInitParam app={0};SceAppUtilBootParam boot={0};
    int rc=sceAppUtilInit(&app,&boot);
    startup_mark("APP UTIL INIT",rc);
    if(rc<0)return 0;
    app_util=true;
    SceCommonDialogConfigParam cfg;
    sceCommonDialogConfigParamInit(&cfg);
    /* The SDK initializer leaves language/confirm button as UINT32_MAX
     * placeholders. Pass actual supported values to the firmware API. */
    int lang=-1, button=-1;
    const int lang_rc=sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_LANG,&lang);
    const int button_rc=sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_ENTER_BUTTON,&button);
    startup_mark("DIALOG LANG QUERY",lang_rc);
    startup_mark("DIALOG BUTTON QUERY",button_rc);
    cfg.language=choose_dialog_language(lang_rc,lang);
    cfg.enterButtonAssign=choose_dialog_confirm(button_rc,button);
    startup_mark("DIALOG LANG CHOSEN",(int32_t)cfg.language);
    startup_mark("DIALOG BUTTON CHOSEN",(int32_t)cfg.enterButtonAssign);
    rc=sceCommonDialogSetConfigParam(&cfg);
    startup_mark("COMMON DIALOG CONFIG",rc);
    if(rc<0)return 0;
    const SceGxmInitializeParams p={.displayQueueMaxPendingCount=1,.displayQueueCallback=show,
        .displayQueueCallbackDataSize=sizeof(void*),.parameterBufferSize=SCE_GXM_DEFAULT_PARAMETER_BUFFER_SIZE};
    rc=sceGxmInitialize(&p);
    startup_mark("GXM INIT",rc);
    if(rc<0)return 0;
    gxm=true;
    for(unsigned i=0;i<2;i++) {
        struct Frame *f=&buf[i];
        f->id=sceKernelAllocMemBlock("InaSshFb",SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW,FB_BYTES,NULL);
        startup_mark("FRAME BUFFER ALLOC",f->id);
        if(f->id<0)return 0;
        rc=sceKernelGetMemBlockBase(f->id,&f->data);
        startup_mark("FRAME BUFFER BASE",rc);
        if(rc<0||!f->data)return 0;
        rc=sceGxmMapMemory(f->data,FB_BYTES,SCE_GXM_MEMORY_ATTRIB_READ|SCE_GXM_MEMORY_ATTRIB_WRITE);
        startup_mark("GXM FRAME MAP",rc);
        if(rc<0)return 0;
        f->mapped=true;
        rc=sceGxmColorSurfaceInit(&f->surface,SCE_GXM_COLOR_FORMAT_A8B8G8R8,SCE_GXM_COLOR_SURFACE_LINEAR,
           SCE_GXM_COLOR_SURFACE_SCALE_NONE,SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT,W,H,PITCH,f->data);
        startup_mark("GXM SURFACE INIT",rc);
        if(rc<0)return 0;
        rc=sceGxmSyncObjectCreate(&f->sync);
        startup_mark("GXM SYNC OBJECT",rc);
        if(rc<0)return 0;
    }
    return 1;
}
static uint64_t last_xfer_present;
static int frame(const char *label,const char *pin,int dialog,const char *hint,
                 bool terminal,bool agent_online,bool transfer,const wb_xfer_ui *meter,uint64_t now){
    struct Frame *f=&buf[cursor];
    uint32_t *pixels=f->data;
    const uint32_t fg=COLOR(224,235,227);
    const uint32_t bg=terminal?LIVE_TERMINAL_BG:COLOR(16,24,38);
    if(terminal){
        const struct Frame *shown=&buf[cursor^1];
        if(!agent_online||wb_mirror_browsing())meter=NULL;
        /* Only skip if the DISPLAYED buffer already has this exact image;
         * the back buffer may still contain a different revision. Retain a
         * periodic heartbeat and never skip dialogs, idle or wake transitions. */
        if(transfer && last_xfer_present && now>=last_xfer_present && now-last_xfer_present<1000 &&
           wb_panel_matches(&shown->mirror_cache,wb_mirror_revision(),agent_online,pin,hint) &&
           wb_xfer_matches(shown->meter.text[0]?&shown->meter:NULL,meter))return 1;
        const bool base_dirty=wb_panel_needs_raster(&f->mirror_cache,wb_mirror_revision(),agent_online,pin,hint);
        const bool meter_dirty=!wb_xfer_matches(f->meter.text[0]?&f->meter:NULL,meter);
        if(base_dirty||(!meter&&meter_dirty)){
            for(unsigned i=0;i<PITCH*H;i++)pixels[i]=bg;
            draw_mirror(pixels,pin,hint,agent_online);
        }
        if(meter && (base_dirty||meter_dirty))wb_xfer_draw(pixels,meter);
        if(meter)f->meter=*meter;else f->meter.text[0]=0;
    }else{
        f->mirror_cache.valid=false;
        f->meter.text[0]=0;
        for(unsigned i=0;i<PITCH*H;i++)pixels[i]=bg;
        (void)pin; /* Host key fingerprint is shown in the PC terminal, not on Vita. */
        draw(pixels,35,4,"VITA AGENT WORKBENCH",COLOR(250,240,220));
        draw(pixels,130,3,label,COLOR(120,255,163));
        draw(pixels,220,3,"192.0.2.10:2222 - AGENT MODE",fg);
        if(hint)draw(pixels,320,3,hint,fg);
        if(!dialog)draw(pixels,435,3,"START EXITS",fg);
    }
    if(dialog) {
        SceCommonDialogUpdateParam p={0};
        p.renderTarget.colorSurfaceData=pixels;p.renderTarget.surfaceType=SCE_GXM_COLOR_SURFACE_LINEAR;
        p.renderTarget.colorFormat=SCE_GXM_COLOR_FORMAT_A8B8G8R8;
        p.renderTarget.width=W;p.renderTarget.height=H;p.renderTarget.strideInPixels=PITCH;
        p.displaySyncObject=f->sync;
        if(sceCommonDialogUpdate(&p)<0)return 0;
    }
    if(sceGxmPadHeartbeat(&f->surface,f->sync)<0||
       sceGxmDisplayQueueAddEntry(buf[cursor^1].sync,f->sync,&f->data)<0||
       sceGxmDisplayQueueFinish()<0)return 0;
    last_xfer_present=transfer?now:0;
    cursor^=1;return 1;
}
int display_frame_prompt(const char *label,const char *pin,int dialog,const char *hint) {
    return frame(label,pin,dialog,hint,false,false,false,NULL,0);
}
int display_terminal(const char *host_pin,const char *event,bool agent_online) {
    return frame(NULL,host_pin,0,event,true,agent_online,false,NULL,0);
}
int display_terminal_transfer(const char *pin,const char *event,bool online,const wb_xfer_ui *meter,uint64_t now){
    return frame(NULL,pin,0,event,true,online,true,meter,now);
}
int display_frame(const char *label,const char *pin,int dialog) {
    return display_frame_prompt(label,pin,dialog,NULL);
}
static void put32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

/* The frame just handed to the display queue is buf[cursor ^ 1]. */
int display_capture(const char *path) {
    const struct Frame *f = &buf[cursor ^ 1];
    if (!path || !f->data) return 0;
    const uint32_t *px = (const uint32_t *)f->data;
    const int row = (W * 3 + 3) & ~3;
    const uint32_t image = (uint32_t)(row * H);
    uint8_t hdr[54];
    for (unsigned i = 0; i < sizeof hdr; i++) hdr[i] = 0;
    hdr[0] = 'B'; hdr[1] = 'M';
    put32le(hdr + 2, 54u + image);
    put32le(hdr + 10, 54u);
    put32le(hdr + 14, 40u);
    put32le(hdr + 18, (uint32_t)W);
    put32le(hdr + 22, (uint32_t)H);
    put16le(hdr + 26, 1);
    put16le(hdr + 28, 24);
    put32le(hdr + 34, image);
    put32le(hdr + 38, 2835u);
    put32le(hdr + 42, 2835u);

    const int fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (fd < 0) return 0;
    if (sceIoWrite(fd, hdr, sizeof hdr) != (int)sizeof hdr) { (void)sceIoClose(fd); return 0; }
    static uint8_t line[3 * 960 + 4];
    for (int y = H - 1; y >= 0; y--) {
        const uint32_t *src = px + (unsigned)y * PITCH;
        for (int x = 0; x < W; x++) {
            const uint32_t v = src[x];
            /* Framebuffer packs R into the low byte; BMP rows store B,G,R. */
            line[3 * x + 0] = (uint8_t)((v >> 16) & 0xFF);
            line[3 * x + 1] = (uint8_t)((v >> 8) & 0xFF);
            line[3 * x + 2] = (uint8_t)(v & 0xFF);
        }
        for (int x = W * 3; x < row; x++) line[x] = 0;
        if (sceIoWrite(fd, line, (SceSize)row) != row) { (void)sceIoClose(fd); return 0; }
    }
    (void)sceIoSyncByFd(fd, 0);
    return sceIoClose(fd) >= 0;
}

void display_close(void) {
    if(gxm)sceGxmDisplayQueueFinish();
    sceDisplaySetFrameBuf(NULL,SCE_DISPLAY_SETBUF_IMMEDIATE);
    for(unsigned i=0;i<2;i++){
        if(buf[i].data){
            volatile uint32_t *clear=(volatile uint32_t *)buf[i].data;
            for(unsigned j=0;j<PITCH*H;j++)clear[j]=0;
        }
        if(buf[i].sync)sceGxmSyncObjectDestroy(buf[i].sync);
        if(buf[i].mapped)sceGxmUnmapMemory(buf[i].data);
        if(buf[i].id>=0)sceKernelFreeMemBlock(buf[i].id);
    }
    if(gxm)sceGxmTerminate();
    if(app_util)sceAppUtilShutdown();
}

void display_plain_error(const char *label) {
    SceUID id=sceKernelAllocMemBlock("InaSshError",SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW,FB_BYTES,NULL);
    void *mem=NULL;
    if(id<0)return;
    if(sceKernelGetMemBlockBase(id,&mem)>=0&&mem){
        uint32_t *fb=mem;
        for(unsigned i=0;i<PITCH*H;i++)fb[i]=COLOR(16,24,38);
        draw(fb,55,4,"VITA AGENT WORKBENCH",COLOR(250,240,220));
        draw(fb,160,3,label,COLOR(240,150,150));
        draw(fb,240,3,"SEE STARTUP.LOG",COLOR(250,240,220));
        const SceDisplayFrameBuf p={.size=sizeof p,.base=mem,.pitch=PITCH,
            .pixelformat=SCE_DISPLAY_PIXELFORMAT_A8B8G8R8,.width=W,.height=H};
        if(sceDisplaySetFrameBuf(&p,SCE_DISPLAY_SETBUF_NEXTFRAME)>=0) {
            sceKernelDelayThread(6000000);
            if(sceDisplaySetFrameBuf(NULL,SCE_DISPLAY_SETBUF_IMMEDIATE)<0)return;
        }
    }
    sceKernelFreeMemBlock(id);
}
