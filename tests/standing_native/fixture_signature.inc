/* Signature verification has its own independent crypto/format suite.
 * In these native storage/authority fixtures exercise success and tamper
 * on the exact production interface, with no private or signing key. */
#define WB_STANDING_VERIFY_H
#include "focus_guard.h"
#include "startup_power.h"
enum{MODE_B_KEY=2};
static struct {int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static bool has_fg=true,has_audit=true,corrupt_signature,signature_power;
static unsigned tried_signatures;
typedef struct {
    int cb,app_rc,rtc_rc;
    uint32_t power;
    bool power_latched;
    struct {uint32_t appEventNum,systemEventNum;bool isSystemUiOverlaid;} state;
    SceRtcTick tick;
} FocusEvidence;
static uint32_t fg_app,fg_system,fg_power;
static int fg_callback,fg_app_rc,fg_rtc_rc;
static bool fg_latched;
static uint64_t sceKernelGetProcessTimeWide(void){return mono*1000;}
/* 01.91 bounded-settle model: the delay stub advances the fixture clock so a
 * bounded loop terminates, and the power trio is steered per case. */
static int pw_ac=1,pw_suspend=0,pw_low=0;
static int scePowerIsPowerOnline(void){return pw_ac;}
static int scePowerIsSuspendRequired(void){return pw_suspend;}
static int scePowerIsLowBattery(void){return pw_low;}
/* Clock model: wall is RTC microseconds, mono is milliseconds. A delay must
 * advance BOTH by the same wall time so a bracket skew check stays honest. */
static int sceKernelDelayThread(unsigned us){mono+=us/1000u;wall+=us;return 0;}
static int overlay_reads;
static FocusEvidence read_focus(void){
    /* fg_* are the case's steady state; a.power_event/a.power_latched are the
     * real listener fields, so a settle that absorbs them is observable. */
    FocusEvidence e={.cb=fg_callback,.app_rc=fg_app_rc,.rtc_rc=fg_rtc_rc,
                     .power=fg_power|a.power_event,.power_latched=fg_latched||a.power_latched,
                     .state={fg_app,fg_system,!has_fg||overlay_reads>0},.tick={wall}};
    if(overlay_reads>0)--overlay_reads;   /* an overlay that clears by itself */
    return e;
}
static void capture_focus(const FocusEvidence *e){a.rtc_last=e->tick.tick;}
static FocusResult classify(const FocusEvidence *e,bool capture){
    return focus_result(e->cb,e->power_latched?1u:e->power,e->app_rc,e->state.isSystemUiOverlaid,
        e->rtc_rc,e->tick.tick,capture,!e->state.appEventNum&&!e->state.systemEventNum,a.rtc_last);
}
enum{SCE_CTRL_SELECT=1,SCE_CTRL_START=2,SCE_CTRL_CROSS=4};
enum{SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND=1,SCE_KERNEL_POWER_TICK_DISABLE_OLED_OFF=4};
/* The release-scoped enrollment has independent physical-gesture tests. These
 * old standing/signature tests never invoke it; retain SDK-link completeness. */
static int sceKernelPowerTick(int flags){assert(flags==1||flags==4);return 0;}
static int display_frame_prompt(const char *label,const char *pin,int dialog,const char *hint){
    assert(label&&!pin&&!dialog&&hint);return 1;
}
typedef struct{unsigned buttons;} SceCtrlData;
static unsigned pads;
static bool bad_input;
static int sceCtrlPeekBufferPositive(int port,SceCtrlData *p,int count){
    assert(!port&&count==1);p->buttons=pads;return !bad_input;}
static inline bool foreground(bool capture){assert(!capture);return has_fg;}
/* Bounded echo of the last log lines, for a failing case only. */
static char log_ring[8][160];static unsigned log_seen;static bool show_log;
#if defined(__GNUC__)
__attribute__((unused))
#endif
static void dump_log(void){
    if(!show_log)return;
    for(unsigned i=0;i<8&&i<log_seen;i++)fprintf(stderr,"LOG %s\n",log_ring[(log_seen+i)%8]);
}
static bool log_event(const char *text){
    assert(text&&*text);
    snprintf(log_ring[log_seen%8],sizeof log_ring[0],"%s",text);++log_seen;
    return has_audit;
}
static const char *wb_standing_key_id(void){return "1111111111111111111111111111111111111111111111111111111111111111";}
static bool wb_standing_provisioned(const char *h,const char *o){
    char hn[65],on[65];return wb_r1_normal_pin(hn,h)&&wb_r1_normal_pin(on,o)&&
        wb_r1_pin_equal(hn,host)&&wb_r1_pin_equal(on,own);
}
static bool wb_standing_verify(const char *receipt,const char *source,const char *run,
      const char *host_pin,const char *owner_pin,const char *r,const char *s) {
    ++tried_signatures;
    if(signature_power)++a.power_calls;
    return !corrupt_signature && wb_r1_receipt(receipt,NULL) &&
        !strcmp(source,WB_STANDING_BOOTSTRAP?"01.84":"01.85")
        && !strcmp(run,a.run_hex) && wb_standing_provisioned(host_pin,owner_pin)
        && !strcmp(r,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        && !strcmp(s,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}
