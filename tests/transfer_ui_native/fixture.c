#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_screen_mirror.h"
#include "active_terminal.h"
#include "wb_panel_cache.h"
#include "wb_xfer_ui.h"
enum {W=960,H=544,PITCH=1024};
#include "screen.inc"
#include "mirror_panel.inc"
#include "wb_xfer_panel.inc"
static uint32_t px[2][H*PITCH],ref[H*PITCH];
static int syncids[2];
static struct Frame{uint32_t *data;int surface,*sync;wb_panel_cache mirror_cache;wb_xfer_ui meter;}
 buf[2]={{.data=px[0],.sync=&syncids[0]},{.data=px[1],.sync=&syncids[1]}};
static unsigned cursor=1,queued,finished,beat;
typedef struct{struct{void *colorSurfaceData;unsigned surfaceType,colorFormat,width,height,strideInPixels;}renderTarget;int *displaySyncObject;} SceCommonDialogUpdateParam;
enum{SCE_GXM_COLOR_SURFACE_LINEAR=1,SCE_GXM_COLOR_FORMAT_A8B8G8R8=2};
static int sceCommonDialogUpdate(SceCommonDialogUpdateParam*p){assert(p->renderTarget.width==W);return 0;}
static int sceGxmPadHeartbeat(int *surface,int *sync){(void)surface;(void)sync;beat++;return 0;}
static int sceGxmDisplayQueueAddEntry(int *from,int *to,uint32_t **data){assert(from!=to && *data==px[cursor]);queued++;return 0;}
static int sceGxmDisplayQueueFinish(void){finished++;return 0;}
#include "frame.inc"
static void assert_shown(const char *event,const wb_xfer_ui *m){
    for(unsigned i=0;i<H*PITCH;i++)ref[i]=LIVE_TERMINAL_BG;
    draw_mirror(ref,"pin",event,true);
    if(m)wb_xfer_draw(ref,m);
    assert(!memcmp(ref,px[cursor^1],sizeof ref));
    assert(beat==queued&&queued==finished);
}
int main(void){
    wb_mirror_begin();wb_mirror_write((const uint8_t*)"ux0:/> put a\r\n",14);
    const uint64_t rev=wb_mirror_revision();
    wb_xfer_ui a,b,end,zero;
    wb_xfer_format(&a,true,1024,2048,1024);
    wb_xfer_format(&b,true,1536,2048,1500000);
    wb_xfer_format(&end,true,UINT32_MAX,UINT32_MAX,500000);
    wb_xfer_format(&zero,false,0,1024,0);
    assert(!strcmp(a.text,"PUT 50%  1024/2048 B  1.0 KB/s  ETA 1s"));
    assert(strstr(b.text,"1.50 MB/s"));assert(strstr(end.text,"4294967295/4294967295 B")&&strstr(end.text,"WAIT RECEIPT"));
    assert(!strcmp(zero.text,"GET 0%  0/1024 B  0.0 KB/s  ETA --"));
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&a,100));
    assert(queued==1);assert_shown("SSH LISTENING",&a);
    /* Decode the actual '%' glyph and 50% bar edges at the cursor row. */
    const unsigned y=MIR_Y+wb_type_cell_h(wb_type_get()),xp=4+12*6;
    for(unsigned j=0;j<7;j++)for(unsigned i=0;i<5;i++)
        assert((px[cursor^1][(y+1+j*2)*PITCH+xp+i*2]==LIVE_TERMINAL_FG)==!!(mirror_glyph('%')[j]&(1u<<(4-i))));
    assert(px[cursor^1][(y+17)*PITCH+479]==LIVE_TERMINAL_GREEN&&px[cursor^1][(y+17)*PITCH+480]!=LIVE_TERMINAL_GREEN);
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&a,150));assert(queued==1);
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&b,300));assert(queued==2);assert_shown("SSH LISTENING",&b);
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&end,500));assert(queued==3);assert_shown("SSH LISTENING",&end);
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&end,550));assert(queued==3);
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&end,1550));assert(queued==4);assert_shown("SSH LISTENING",&end);
    assert(rev==wb_mirror_revision()); /* no wire or model bytes inserted */
    assert(display_terminal_transfer("pin","R1 AUTHORIZATION REVOKED",true,NULL,1600));assert_shown("R1 AUTHORIZATION REVOKED",NULL);
    assert(display_terminal("pin","SSH LISTENING",true));assert_shown("SSH LISTENING",NULL);
    /* History never gains a live overlay; after typography/reflow footer stays intact. */
    for(int i=0;i<40;i++)wb_mirror_write((const uint8_t*)"sample\r\n",8);
    assert(wb_mirror_scroll(2,WB_PANEL_ROWS));assert(wb_mirror_browsing());
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&b,1900));assert_shown("SSH LISTENING",NULL);
    wb_mirror_follow();assert(wb_type_set((wb_type_style){WB_TYPE_JETBRAINS,3,4,10}));
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&b,2000));assert_shown("SSH LISTENING",&b);
    assert(display_frame_prompt("CHECK POWER STATE",NULL,1,NULL));
    assert(display_terminal_transfer("pin","SSH LISTENING",true,&b,2030));assert_shown("SSH LISTENING",&b);
    puts("PASS native inline meter pixels/percent/ETA, owner notices/history, double-buffer cache, heartbeat skip, dialog restore and unmodified mirror");
}
