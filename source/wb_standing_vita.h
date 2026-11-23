#ifndef WB_STANDING_VITA_H
#define WB_STANDING_VITA_H

#include "wb_standing_verify.h"

/* Authority lives only in application-private savedata. No SSH path can
 * enroll or remove a revocation tombstone. This schema has no ABI padding.
 * 01.91 changes only WHEN a signed bracket is sampled (bounded settle), never
 * WHAT it requires; see the unattended-bracket note further down. */
#define WB_STANDING_NAME "wb-r1-standing-v1.bin"
#define WB_STANDING_PATH "savedata0:/" WB_STANDING_NAME
typedef struct {
    char magic[8],key[65],host[65],owner[65],source_run[17],nonce[33],used[WBQ_CAP];
    unsigned char permit;
} wb_standing_disk;
_Static_assert(sizeof(wb_standing_disk)==353,"standing consent fixed record");
enum { WB_STANDING_ACTIVE=1,WB_STANDING_REVOKED=2 };
static bool standing_disabled_this_run;
static uint32_t standing_power_gen;

static bool wb_standing_saved(const wb_standing_disk *r) {
    SceSize needed=0;wb_standing_disk got={0};
    SceAppUtilSaveDataFile f={.filePath=WB_STANDING_NAME,.buf=(void *)r,.bufSize=sizeof *r,
                              .mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    return sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&needed)==0 &&
           r1_get(WB_STANDING_PATH,&got,sizeof got) && !memcmp(r,&got,sizeof got);
}
static bool wb_standing_used_ok(const char used[WBQ_CAP]) {
    const char *end=memchr(used,0,WBQ_CAP);
    if(!end || (used[0] && !wb_r1_receipt(used,NULL)))return false;
    for(++end;end<used+WBQ_CAP;++end)if(*end)return false;
    return true;
}
static bool wb_standing_active(wb_standing_disk *r) {
    const char *key=wb_standing_key_id();
    return !standing_disabled_this_run && wb_standing_provisioned(a.pin,a.user_pin)
        && wb_r1_hex(key,64,false,true)
        && r1_get(WB_STANDING_PATH,r,sizeof *r) && !memcmp(r->magic,"WBS1-01",8)
        && r->permit==WB_STANDING_ACTIVE && !memcmp(r->key,key,65)
        && wb_r1_pin_equal(r->host,a.pin) && wb_r1_pin_equal(r->owner,a.user_pin)
        && wb_r1_hex(r->source_run,16,true,true) && wb_r1_hex(r->nonce,32,true,true)
        && wb_standing_used_ok(r->used);
}
static bool wb_standing_revoked(void) {
    wb_standing_disk r={0},tomb={.magic="WBS1-01",.permit=WB_STANDING_REVOKED};
    return r1_get(WB_STANDING_PATH,&r,sizeof r) && !memcmp(&r,&tomb,sizeof tomb);
}
/* Call only after completed r1_boot, post-return foreground and bind gates.
 * The private one-shot proof already ties the installed bytes to physical
 * approval of this exact build; an ordinary install can never call this. */
static void wb_standing_bootstrap(const wb_r1_ticket *ret) {
#if defined(WB_STANDING_BOOTSTRAP) && WB_STANDING_BOOTSTRAP
    const char *key=wb_standing_key_id();
    if(standing_disabled_this_run || strcmp(WB_VERSION,"01.84") || !wb_r1_valid(ret,r1_now()) ||
       strcmp(ret->source_ver,"01.82") || strcmp(ret->target_ver,"01.84") ||
       !wb_r1_pin_equal(ret->host_pin,a.pin) || !wb_r1_pin_equal(ret->owner_pin,a.user_pin) ||
       !wb_standing_provisioned(a.pin,a.user_pin) || !wb_r1_hex(key,64,false,true) ||
       r1_exists(WB_STANDING_PATH)!=0 || !foreground(false))return;
    wb_standing_disk record={.magic="WBS1-01",.permit=WB_STANDING_ACTIVE};
    memcpy(record.key,key,65);
    memcpy(record.host,ret->host_pin,65);memcpy(record.owner,ret->owner_pin,65);
    memcpy(record.source_run,ret->source_run,17);memcpy(record.nonce,ret->nonce,33);
    if(!wb_standing_saved(&record)){
        standing_disabled_this_run=true;
        (void)log_event("R1 STANDING BOOTSTRAP SAVE FAILED");
        return;
    }
    (void)log_event("R1 STANDING BOOTSTRAP VERIFIED");
#else
    (void)ret;
#endif
}
/* Local SELECT only. Fail closed in RAM even if persistence itself fails;
 * never show revoked as durable until the exact private bytes read back. */
static bool wb_standing_veto(void) {
    standing_disabled_this_run=true;
    if(wb_standing_revoked())return true;
    wb_standing_disk tomb={.magic="WBS1-01",.permit=WB_STANDING_REVOKED};
    if(!wb_standing_saved(&tomb)){(void)log_event("R1 STANDING REVOKE SAVE FAILED");return false;}
    (void)log_event("R1 STANDING LOCALLY REVOKED");
    return true;
}
static bool wb_standing_owner_pty(void) {
    return g_ssh.authenticated && g_ssh.mode.accepted && g_ssh.mode.mode==MODE_B_KEY &&
        g_ssh.session && g_ssh.channel && g_ssh.shell && g_ssh.shell_pty && !g_ssh.sftp_ro;
}
/* ---- 01.91 unattended bracket -------------------------------------------
 * 01.89/01.90 sampled the console ONCE and refused unless that single sample
 * was pristine. On a console nobody is touching, three already-observed,
 * non-authoritative states made a grant impossible:
 *   (a) a resume/zero-bit registration latched while the PTY was busy - the
 *       listener's absorb pass only runs when g_ssh.busy is false, so a long
 *       put/install leaves the latch standing;
 *   (b) sceCtrlPeekBufferPositive returning no sample - the same condition the
 *       listener already logs as "REMOTE LOCAL INPUT UNKNOWN; SSH KEPT" and
 *       does NOT treat as a press;
 *   (c) a system overlay that clears by itself within a second.
 * None of (a)-(c) is authority. The receipt digest, the P-256 signature, the
 * durable one-shot spend, the TTL/clock, the pin and bind gates, both bracket
 * endpoints and their interval are unchanged. This only replaces one blind
 * sample with a bounded, logged settle so taking a bracket needs no keypress.
 * A real supply change, suspend/low veto, app/RTC/callback error, START,
 * SELECT, or any counter/generation movement INSIDE a bracket still refuses. */
enum { WB_FOCUS_SETTLE_MS=6000u, WB_FOCUS_STEP_MS=20u, WB_FOCUS_RETRY_MS=320u,
       WB_PAD_SAMPLE_MS=120u, WB_PAD_STEP_MS=8u };
static const char *wb_focus_name(FocusResult r) {
    switch(r){
    case FG_OK:return "ok";          case FG_CB_ERR:return "callback";
    case FG_POWER:return "power";    case FG_APPMGR_ERR:return "appmgr";
    case FG_OVERLAY:return "overlay";case FG_RTC_ERR:return "rtc";
    case FG_RTC_ZERO:return "rtc-zero";case FG_COUNTERS:return "counters";
    default:return "rtc-gap";
    }
}
static void wb_focus_note(const char *what) {
    char line[128];
    (void)snprintf(line,sizeof line,"R1 FOCUS %s",what);
    (void)log_event(line);
}
/* Exactly the two shapes the listener already absorbs: a zero-bit registration
 * and AFTER_RESUME whose supply bit agrees with the live supply. */
static bool wb_focus_power_benign(uint32_t bits,int ac,int suspend,int low) {
    if(suspend||low)return false;
    if(!bits)return true;
    const uint32_t known=(uint32_t)(WB_AC_ONLINE|WB_BATTERY_ONLINE|WB_AFTER_RESUME);
    return (bits&(uint32_t)WB_AFTER_RESUME)!=0 && (bits&~known)==0 &&
           (((bits&(uint32_t)WB_AC_ONLINE)!=0)==(ac==1));
}
/* Bounded settle before a bracket opens. Returns the generation the bracket
 * must be anchored to. Never clears a real supply/suspend/low state. */
static bool wb_standing_focus_settle(uint32_t *generation) {
    const uint64_t start=now_ms();unsigned absorbed=0;
    for(;;){
        const FocusEvidence e=read_focus();
        const int ac=scePowerIsPowerOnline(),suspend=scePowerIsSuspendRequired(),low=scePowerIsLowBattery();
        if(e.cb<0||e.app_rc<0||e.rtc_rc<0||!e.tick.tick){wb_focus_note("SETTLE HARD REFUSED");return false;}
        if(suspend||low){wb_focus_note("SETTLE POWER VETO");return false;}
        if(e.power_latched||e.power){
            if(!wb_focus_power_benign(e.power,ac,suspend,low)){wb_focus_note("SETTLE SUPPLY REFUSED");return false;}
            a.power_event=0;a.power_latched=false;
            if(!absorbed++)wb_focus_note("SETTLE ABSORB REGISTRATION");
        }
        /* A sample that passed the hard checks becomes the ordinary baseline,
         * exactly like the listener's idle absorb pass. Without this the strict
         * classifier would judge the window since BEFORE a long PTY command and
         * report FG_COUNTERS/FG_RTC_GAP for a console nobody touched. */
        capture_focus(&e);
        if(!e.state.isSystemUiOverlaid && !e.power && !e.power_latched){
            *generation=a.power_calls;
            if(absorbed)wb_focus_note("SETTLE READY");
            return true;
        }
        const uint64_t t=now_ms();
        if(t<start||t-start>=WB_FOCUS_SETTLE_MS){
            wb_focus_note(e.state.isSystemUiOverlaid?"SETTLE OVERLAY TIMEOUT":"SETTLE TIMEOUT");
            return false;
        }
        sceKernelDelayThread(WB_FOCUS_STEP_MS*1000u);
    }
}
/* A terminal can pipeline both verbs in one SSH service iteration; sample
 * real hardware veto here too, not just in the outer listener loop. A positive
 * press still vetoes; an unavailable pad is unknown, never a press. */
static bool wb_standing_buttons(void) {
    const uint64_t start=now_ms();bool saw_sample=false;
    for(;;){
        SceCtrlData pad={0};
        if(sceCtrlPeekBufferPositive(0,&pad,1)>0){
            saw_sample=true;
            if(pad.buttons&SCE_CTRL_SELECT){(void)wb_standing_veto();wb_focus_note("PAD SELECT VETO");return false;}
            if(pad.buttons&SCE_CTRL_START){wb_focus_note("PAD START VETO");return false;}
            return true;
        }
        const uint64_t t=now_ms();
        if(t<start||t-start>=WB_PAD_SAMPLE_MS){
            if(!saw_sample)wb_focus_note("PAD UNKNOWN NOT A VETO");
            return true;
        }
        sceKernelDelayThread(WB_PAD_STEP_MS*1000u);
    }
}
static bool wb_standing_focus_read(wb_signed_focus *out,bool strict,uint32_t generation) {
    if(!wb_standing_owner_pty())return false;
    const FocusEvidence e=read_focus();
    const FocusResult r=classify(&e,false);
    const bool pad=wb_standing_buttons();
    if(e.cb!=0 || e.power_latched || e.power || e.app_rc<0 || e.rtc_rc<0 ||
       !e.tick.tick || e.state.isSystemUiOverlaid || a.power_calls!=generation ||
       (strict && r!=FG_OK) || !pad) {
        /* Keep the stable refusal marker every reader already greps for, and
         * add the sampled subcondition on a second line. */
        (void)log_event(strict?"R1 SIGNED FOCUS BRACKET START REFUSED":"R1 SIGNED FOCUS BRACKET END REFUSED");
        char line[128];
        (void)snprintf(line,sizeof line,"R1 FOCUS DETAIL why=%s cb=%d over=%u pad=%d gen=%u/%u",
            wb_focus_name(r),e.cb,(unsigned)e.state.isSystemUiOverlaid,
            pad?0:1,(unsigned)a.power_calls,(unsigned)generation);
        (void)log_event(line);
        return false;
    }
    *out=(wb_signed_focus){.rtc_us=e.tick.tick,.mono_us=sceKernelGetProcessTimeWide(),
                           .app_events=e.state.appEventNum,.system_events=e.state.systemEventNum,
                           .power_generation=generation};
    return true;
}
static bool wb_standing_focus_finish(const wb_signed_focus *begin) {
    /* One bounded retry, and never an absorb: the generation must stay the one
     * the bracket opened with, so a transient overlay cannot widen the window. */
    const uint64_t start=now_ms();
    for(;;){
        wb_signed_focus end={0};
        if(wb_standing_focus_read(&end,false,begin->power_generation)){
            if(!wb_signed_focus_interval(begin,&end)){
                (void)log_event("R1 SIGNED FOCUS BRACKET END REFUSED interval");return false;
            }
            /* Keep the ordinary RTC baseline current only after validating BOTH
             * endpoints. Do not clear counters, a power latch or a veto. */
            a.rtc_last=end.rtc_us;
            return true;
        }
        const uint64_t t=now_ms();
        if(t<start||t-start>=WB_FOCUS_RETRY_MS)return false;
        sceKernelDelayThread(WB_FOCUS_STEP_MS*1000u);
    }
}
/* Apply opens its bracket on the SAME power generation the grant settled on:
 * a real power/resume event between consent and dispatch still voids the
 * dispatch (the target is never retried). Only transient sampling is retried,
 * and never by absorbing, so the generation cannot move inside the window. */
static bool wb_standing_apply_begin(wb_signed_focus *begin) {
    const uint64_t start=now_ms();
    for(;;){
        if(wb_standing_focus_read(begin,true,standing_power_gen))return true;
        const uint64_t t=now_ms();
        if(t<start||t-start>=WB_FOCUS_RETRY_MS)return false;
        sceKernelDelayThread(WB_FOCUS_STEP_MS*1000u);
    }
}
static bool wb_standing_apply_end(const wb_signed_focus *begin,const char *receipt) {
    wb_standing_disk r={0};
    return wb_standing_active(&r) && !strcmp(r.used,receipt) && wb_standing_focus_finish(begin);
}
static int wb_standing_status(const wb_cmd *cmd,wb_out *out,int *status) {
    *status=1;
    if(!wb_standing_owner_pty())return wb_out_puts(out,"ERR r1-auto no-pty\n");
    if(cmd->argc!=0)return wb_out_puts(out,"ERR r1-auto usage\n");
    wb_standing_disk r={0};
    const char *state=wb_standing_active(&r)?"enabled":wb_standing_revoked()?"revoked":"disabled";
    *status=0;
    return wb_out_printf(out,"r1-auto state=%s run=%s\n",state,a.run_hex);
}
static int wb_standing_issue(const wb_cmd *cmd,wb_out *out,int *status) {
    *status=1;
    if(!wb_standing_owner_pty())return wb_out_puts(out,"ERR r1-signed no-pty\n");
    if(cmd->argc!=2 || !wb_notice_hex(cmd->argv[0]) || !wb_notice_hex(cmd->argv[1]))
        return wb_out_puts(out,"ERR r1-signed usage\n");
    wb_standing_disk priv={0};char receipt[WBQ_CAP]={0},target[6]={0};char previous[6]={0};
    if(!wb_standing_active(&priv))return wb_out_puts(out,"ERR r1-signed disabled\n");
    /* 01.91: settle first (bounded), then anchor the bracket to the generation
     * the settle itself observed. A genuine interruption still refuses. */
    uint32_t power=0;wb_signed_focus check={0};
    if(r1_bound || r1_source_live || !wb_standing_focus_settle(&power) ||
       !wb_standing_focus_read(&check,true,power) || !r1_queue(receipt) ||
       !wb_r1_receipt(receipt,target) || strcmp(target,WB_VERSION)<=0 ||
       (priv.used[0] && (!wb_r1_receipt(priv.used,previous)||strcmp(target,previous)<=0)))
        return wb_out_puts(out,"ERR r1-signed stale-or-busy\n");
    if(!wb_standing_verify(receipt,WB_VERSION,a.run_hex,a.pin,a.user_pin,cmd->argv[0],cmd->argv[1]))
        return wb_out_puts(out,"ERR r1-signed signature\n");
    if(!wb_standing_focus_finish(&check) || !wb_standing_focus_read(&check,true,power))
        return wb_out_puts(out,"ERR r1-signed stale-or-busy\n");
    /* Persist the one signed attempt before mint. A write failure does not
     * authorize retry: there may be durable partial state or a missing ACK. */
    memset(priv.used,0,sizeof priv.used);memcpy(priv.used,receipt,strlen(receipt)+1);
    if(!log_event("R1 SIGNED CONSENT ACCEPTED; SPENDING TARGET") || !wb_standing_saved(&priv)){
        standing_disabled_this_run=true;
        return wb_out_puts(out,"ERR r1-signed storage\n");
    }
    if(r1_issue_ticket(receipt,wb_standing_focus_finish,&check)!=WB_OK)
        return wb_out_puts(out,"ERR r1-signed grant\n");
    standing_power_gen=power;r1_signed_armed=true;
    r1_signed_begin=wb_standing_apply_begin;r1_signed_end=wb_standing_apply_end;
    *status=0;
    return wb_out_printf(out,"OK r1-signed target=%s run=%s manifest=%.64s grant=armed\n",
                         target,a.run_hex,receipt+11);
}

#endif
