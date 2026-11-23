/* Explicit owner-authorized listener recovery, not an update grant.
 * The two public pins remain checked against an existing complete identity.
 * No mutable flag or unavailable local input can create or replace trust. */
#ifndef WB_REMOTE_START_VITA_H
#define WB_REMOTE_START_VITA_H
#define WB_REMOTE_START_OWNER_AUTHORIZED 1
static inline bool remote_start_allowed(void) {
    return WB_REMOTE_START_OWNER_AUTHORIZED && quick_enabled() && quick_pair_is_enrolled();
}
/* Background/lock may withhold pad samples. Unknown is not a fabricated
 * neutral key or a new approval. An actually observed local veto still wins. */
static inline bool remote_start_veto(void) {
    SceCtrlData pad={0};
    if(sceCtrlPeekBufferPositive(0,&pad,1)<=0){
        (void)log_event("REMOTE LOCAL INPUT UNKNOWN; NO APPROVAL CREATED");return false;
    }
    return (pad.buttons&(SCE_CTRL_START|SCE_CTRL_SELECT))!=0;
}
static inline bool remote_start_observe(const char *phase) {
    const FocusEvidence e=read_focus();char note[120];
    (void)snprintf(note,sizeof note,"REMOTE FOCUS %s cb=%d app=%d overlay=%d rtc=%d bits=%08X",
        phase,e.cb,e.app_rc,(int)e.state.isSystemUiOverlaid,e.rtc_rc,(unsigned)e.power);
    if(!log_event(note))return false;
    (void)snprintf(note,sizeof note,"REMOTE POWER %s ac=%d suspend=%d low=%d gen=%u",
        phase,scePowerIsPowerOnline(),scePowerIsSuspendRequired(),scePowerIsLowBattery(),(unsigned)a.power_calls);
    return log_event(note);
}
/* Read-only evidence for the explicit recovery route, which has no R1
 * returned proof. Failure is observable but never bricks the paired listener. */
static inline void remote_start_installed_audit(void) {
    char receipt[WBQ_CAP]={0},version[6]={0},note[120];
    int rc=wq_installed_receipt("ux0:app/" WB_TITLE_ID,WB_VERSION,receipt);
    if(rc==WB_OK && (!wb_r1_receipt(receipt,version) || strcmp(version,WB_VERSION)))rc=WB_E_STATE;
    if(rc==WB_OK){
        char *nl=strchr(receipt,'\n');if(nl)*nl=0;
        (void)snprintf(note,sizeof note,"INSTALLED WBQ2 %s",receipt+5);
    }else (void)snprintf(note,sizeof note,"INSTALLED WBQ2 AUDIT ERROR rc=%d",rc);
    (void)log_event(note);
}
#endif
