/* Host-only. drain.inc, inactive.inc and gate.inc are extracted unmodified
 * from the input release by run.py. No SSH or SDK is linked. */
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "wb_ver.h"
#include "startup_power.h"
#include "fresh_choice.h"
enum {WB_OK=0,SCE_CTRL_START=1,SCE_CTRL_SELECT=2,SCE_CTRL_CROSS=8,WB_Q_DIRECT=2,WB_Q_REMEMBERED=4};
typedef enum { FG_OK, FG_BAD } FocusResult;
typedef struct { unsigned buttons; } SceCtrlData;
typedef struct{int cb,app_rc,rtc_rc;struct{unsigned isSystemUiOverlaid,appEventNum,systemEventNum;}state;struct{uint64_t tick;}tick;} FocusEvidence;
static struct {unsigned power_calls,power_event;int power_notify_count;bool power_latched;unsigned app_event,sys_event;uint64_t rtc_last;char run_hex[17],user_pin[65],ip[16],peer[1][16];int peer_count;} a;
static struct {char host_pin[65];} g_ssh;
static struct {char source_run[17],nonce[33];}ret;
static uint64_t ms=1;static int first_cb=1,reads,ac=1,low,suspend_req,bad_focus,focus_after,flip_ac,repeat;
static int quick_ok=1,qr=WB_Q_REMEMBERED,return_ok,consumed,return_intent;
/* Historical manual/unpaired power path; owner remote policy is tested separately. */
static const bool remote_start=false;
static int prompt_count,ack_reads,phase,ack_manual,ack_cancel,ack_panel_bad,ack_input_bad;
static int launch_veto,return_input_bad,quick_pair_bad,net_count,opens,after_pads,saw_auto,saw_wait,diag_fail;
static const char *screen="",*hint="";
static char diag[32]="-";
static bool log_event(const char *s){if(!strcmp(s,"RETURN AUTO ACK RESUME"))saw_auto++;if(strstr(s,"WAIT LOCAL ACK"))saw_wait++;return true;}
static int timeline_event(const char *evt,const char *before,const char *after){(void)evt;(void)before;(void)after;return 0;}
static FocusEvidence read_focus(void){FocusEvidence e={0};e.cb=reads++==0?first_cb:0;e.tick.tick=ms+1;return e;}
static FocusResult focus_result(int cb,int power,int arc,int overlay,int rrc,uint64_t tick,bool cap,bool same,uint64_t last){
    (void)cb;(void)power;(void)arc;(void)overlay;(void)rrc;(void)tick;(void)cap;(void)same;(void)last;return bad_focus?FG_BAD:FG_OK;
}
static int scePowerIsPowerOnline(void){return ac;}
static int scePowerIsSuspendRequired(void){return suspend_req;}
static int scePowerIsLowBattery(void){return low;}
static uint64_t now_ms(void){return ms;}
static void sceKernelDelayThread(int us){ms+=us/1000;if(ms>40000)abort();if(flip_ac&&ms>=100)ac=0;if(repeat&&ms>=100)a.power_calls=2;}
static bool display_frame_prompt(const char *l,const char *pin,int d,const char *h){assert(l&&!pin&&!d&&h);
    if(!strcmp(l,"CHECK POWER STATE")){phase=1;prompt_count++;return !ack_panel_bad;}
    phase=2;screen=l;hint=h;return true;}
static int sceCtrlPeekBufferPositive(int port,SceCtrlData *pad,int n){assert(!port&&n==1);
    if(phase==2){pad->buttons=SCE_CTRL_START;return 1;} /* Leave inactive_screen after recording label/hint */
    if(phase==1){phase=0;ack_reads++;pad->buttons=ack_manual?(ack_reads==1?SCE_CTRL_CROSS:ack_reads==2?0:SCE_CTRL_CROSS):ack_cancel?(ack_reads>1?SCE_CTRL_START:0):0;return !ack_input_bad;}
    after_pads++;pad->buttons=launch_veto?SCE_CTRL_START:0;return !return_input_bad;
}
static int wq_save(const char *p,const void *b,size_t n){assert(p&&n<448);
    const char *s=strstr(b," reason=");assert(s&&sscanf(s," reason=%31s",diag)==1);
    return diag_fail?-1:0;}
static bool foreground(bool v){assert(!v);return !focus_after;}
static int wb_r1_valid(const void *p,uint64_t t){(void)p;(void)t;return 1;}
static uint64_t r1_now(void){return 10;}
static bool quick_veto(void){return launch_veto;}
static inline bool remote_start_veto(void){return quick_veto();}
static inline bool remote_start_observe(const char*p){(void)p;return true;}
static inline void remote_start_installed_audit(void){}
static int quick_pref(void){return 1;}
static bool quick_enabled(void){return true;}
static bool wb_quick_pair(const char *l,const char *r){(void)l;(void)r;return !quick_pair_bad;}
static const char *prep_listener(void){return NULL;}
static bool net_setup(void){net_count++;return true;}
static int wb_ssh_open(const void *w,const char *ip,int port,const char (*peers)[16],int cnt){
    (void)w;(void)ip;(void)port;(void)peers;(void)cnt;opens++;return WB_OK;}
#include "drain.inc"
#include "inactive.inc"
static void drive_startup(void){
    const char *reason=NULL;
    const uint64_t registration=0;
    #include "gate.inc"
    return;
out:
    (void)inactive_screen(reason);
}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    const char *s=argv[1];a.power_event=0x1100;a.power_calls=1;a.power_notify_count=1;
    strcpy(a.run_hex,"5DE8ABEBD83AAD5E");strcpy(ret.source_run,"E1C72ACB5F4C96BE");
    if(!strcmp(s,"observed-low"))low=1;
    else if(!strcmp(s,"low-log-write-fails")){low=1;diag_fail=1;}
    else if(!strcmp(s,"low-no-ac")){low=1;ac=0;a.power_event=0x100;}
    else if(!strcmp(s,"low-invalid-sample"))low=-1;
    else if(!strcmp(s,"suspend-and-low")){low=1;suspend_req=1;}
    else if(!strcmp(s,"normal")){}
    else if(!strcmp(s,"auto")||!strcmp(s,"auto-bad-panel")||!strcmp(s,"auto-bad-ack-input")||
            !strcmp(s,"auto-quick-veto")||!strcmp(s,"auto-r1-veto")||!strcmp(s,"auto-r1-bad-veto-input")||
            !strcmp(s,"auto-focus-after")||!strcmp(s,"auto-bad-pair")){
        a.power_event=0x1080;ack_panel_bad=!strcmp(s,"auto-bad-panel");ack_input_bad=!strcmp(s,"auto-bad-ack-input");
        bad_focus=0;focus_after=!strcmp(s,"auto-focus-after");quick_pair_bad=!strcmp(s,"auto-bad-pair");
        if(!strcmp(s,"auto-r1-veto")||!strcmp(s,"auto-r1-bad-veto-input")){return_ok=1;quick_ok=0;}
        return_input_bad=!strcmp(s,"auto-r1-bad-veto-input");
        launch_veto=!strcmp(s,"auto-r1-veto")||!strcmp(s,"auto-quick-veto");
    }else if(!strcmp(s,"manual-fresh")||!strcmp(s,"manual-cancel")||!strcmp(s,"manual-ack-input-failed")||!strcmp(s,"manual-panel-failed")){
        quick_ok=0;a.power_event=0x1080;ack_manual=!strcmp(s,"manual-fresh");ack_cancel=!strcmp(s,"manual-cancel");
        ack_input_bad=!strcmp(s,"manual-ack-input-failed");ack_panel_bad=!strcmp(s,"manual-panel-failed");
    }else if(!strcmp(s,"focus"))bad_focus=1;
    else if(!strcmp(s,"callback"))first_cb=2;
    else if(!strcmp(s,"clock"))ms=600;
    else if(!strcmp(s,"late"))ms=210;
    else if(!strcmp(s,"supply-change"))flip_ac=1;
    else if(!strcmp(s,"repeat"))repeat=1;
    else if(!strcmp(s,"flags"))a.power_event|=0x40000000;
    else if(!strcmp(s,"ac-mismatch"))ac=0;
    else return 2;
    drive_startup();
    printf("{\"label\":\"%s\",\"hint\":\"%s\",\"ssh_open_calls\":%d,\"net_setup_calls\":%d,\"diag\":\"%s\",\"power_prompts\":%d,\"ack_pad_reads\":%d,\"postgate_pad_reads\":%d,\"auto_ack\":%d,\"wait_ack_log\":%d}\n",screen,hint,opens,net_count,diag,prompt_count,ack_reads,after_pads,saw_auto,saw_wait);
    return 0;
}
