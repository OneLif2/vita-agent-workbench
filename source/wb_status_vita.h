#ifndef WB_STATUS_VITA_H
#define WB_STATUS_VITA_H

/* Owner-only live diagnostic. These independent samples say neither that
 * a particular system dialog is showing nor that an update is authorized.
 * Never clear latched events/recapture focus, arm notices, mutate queues or
 * expose addresses, BSSID/SSID, pins, manifests or device credentials. */
static const char *wb_status_focus_name(FocusResult f) {
    switch(f){
        case FG_OK:return "ok";
        case FG_CB_ERR:return "callback";
        case FG_POWER:return "power";
        case FG_APPMGR_ERR:return "appmgr";
        case FG_OVERLAY:return "overlay";
        case FG_RTC_ERR:return "rtc";
        case FG_RTC_ZERO:return "rtc-zero";
        case FG_COUNTERS:return "counters";
        case FG_RTC_GAP:return "rtc-gap";
        default:return "unknown";
    }
}
static const char *wb_status_foreground(FocusResult f) {
    switch(f){
        case FG_OK:return "ready";
        case FG_POWER:case FG_OVERLAY:case FG_COUNTERS:case FG_RTC_GAP:return "blocked";
        default:return "unknown";
    }
}
static const char *wb_status_queue(char target[6]) {
    const int pub=r1_exists(WB_PENDING_PATH),seal=r1_exists(WBQ_SEAL);
    if(pub==0 && seal==0)return "empty";
    if(pub!=1 || seal!=1)return "unknown";
    /* Marker agreement only; do not hash 4 stage members on a status call. */
    char a0[WBQ_CAP]={0},p0[WBQ_CAP]={0},v[6]={0};size_t an=0,pn=0;
    if(wb_vita_read_small(WB_PENDING_PATH,a0,sizeof a0-1,&an)!=WB_OK ||
       wb_vita_read_small(WBQ_SEAL,p0,sizeof p0-1,&pn)!=WB_OK ||
       !an || an>=sizeof a0 || an!=pn || memchr(a0,0,an) ||
       memcmp(a0,p0,an) || !wb_r1_receipt(a0,v) || strcmp(v,WB_VERSION)<=0)
        return "unknown";
    memcpy(target,v,sizeof v);
    return "pending";
}
static void wb_status_network(const char **link,const char **wifi) {
    *link=*wifi="unknown";
    int state=-1;
    if(!a.ctl || sceNetCtlInetGetState(&state)!=0)return;
    switch(state){
        case SCE_NETCTL_STATE_DISCONNECTED:*link=*wifi="disconnected";return;
        case SCE_NETCTL_STATE_CONNECTING:*link="connecting";return;
        case SCE_NETCTL_STATE_FINALIZING:*link="finalizing";return;
        case SCE_NETCTL_STATE_CONNECTED:break;
        default:return;
    }
    SceNetCtlInfo info={0};info.device=UINT32_MAX;
    const int info_rc=sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_DEVICE,&info);
    /* The link may be moving while we sample the selected interface. */
    int recheck=-1;if(sceNetCtlInetGetState(&recheck)!=0 || recheck!=state)return;
    *link="connected";
    if(info_rc!=0)return;
    /* VitaSDK exposes the device field; SDL_net's Vita adapter maps its
     * platform values to wlan0 (0), eth0 (1), and phone0 (2). */
    if(info.device==0)*wifi="connected";
    else if(info.device==1 || info.device==2)*wifi="not-wifi";
}
static int wb_status_snapshot(const wb_cmd *cmd,wb_out *out,int *status) {
    *status=1;
    if(!wb_standing_owner_pty() || !wb_ssh_connected(&g_ssh))return wb_out_puts(out,"ERR wb-status no-pty\n");
    if(cmd->argc!=0)return wb_out_puts(out,"ERR wb-status usage\n");
    const char *link,*wifi;
    wb_status_network(&link,&wifi);
    char target[6]="-";
    const char *queue=wb_status_queue(target);
    wb_standing_disk r={0};
    const char *standing=wb_standing_active(&r)?"enabled":wb_standing_revoked()?"revoked":
                         r1_exists(WB_STANDING_PATH)==0?"disabled":"unknown";
    const FocusEvidence e=read_focus(); /* dispatches OS callbacks, never clears their latch */
    const FocusResult focus=classify(&e,false);
    const char *overlay=e.app_rc<0?"unknown":e.state.isSystemUiOverlaid==0?"no":
                        e.state.isSystemUiOverlaid==1?"yes":"unknown";
    const char *fg=wb_status_foreground(focus);
    const char *why=wb_status_focus_name(focus);
    if(!strcmp(overlay,"unknown") && (focus==FG_OK || focus==FG_OVERLAY)){fg=why="unknown";}
    const int rc=wb_out_printf(out,
        "OK wb-status version=" WB_VERSION " run=%s uptime_ms=%" PRIu64 "\n"
        "state wb=running lock=unknown overlay=%s foreground=%s focus_reason=%s\n"
        "network link=%s wifi=%s ssh_listener=%s ssh_session=paired\n"
        "update queue=%s target=%s standing=%s\n"
        "END wb-status\n",a.run_hex,now_ms(),overlay,fg,why,link,wifi,
        g_ssh.listening?"listening":"closed",queue,target,standing);
    if(rc>=0)*status=0;
    return rc;
}

#endif
