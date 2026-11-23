#ifndef WB_WAKE_PROBE_VITA_H
#define WB_WAKE_PROBE_VITA_H
/* An owner-issued finite diagnostic, NOT a receiver, wake grant or close guard.
 * Public result data can be forged by another privileged native app; never use
 * it as authority to exit WB. The private pending record only binds this job. */
#include "../wake-probe/wake_probe_protocol.h"
#include "wb_wake_probe_approved.h"
#define WB_PROBE_PRIVATE_NAME "wb-wake-probe-v1.bin"
#define WB_PROBE_PRIVATE_PATH "savedata0:/" WB_PROBE_PRIVATE_NAME
#define WB_PROBE_DIR "ux0:/data/INAP00018/wake-probe"
#define WB_PROBE_TEMP WP_JOB_PATH ".new"

/* Observation only: preserve the FIRST failed operation, including its actual
 * API return. A wb_reader result is a WB abstraction, not a raw native errno;
 * predicate failures have no native API failure and are labelled accordingly. */
typedef struct {
    const char *phase,*operation,*rc_kind;
    int rc,member;
} wb_probe_diagnostic;
static bool wb_probe_failed(wb_probe_diagnostic *d,const char *phase,
        const char *operation,int rc,const char *rc_kind) {
    if(d && !d->phase){d->phase=phase;d->operation=operation;d->rc=rc;d->rc_kind=rc_kind;}
    return false;
}
static bool wb_probe_exact_d(const char *path,void *dst,size_t bytes,
        wb_probe_diagnostic *d,const char *phase) {
    SceIoStat st={0};
    int rc=sceIoGetstat(path,&st);
    if(rc<0)return wb_probe_failed(d,phase,"stat",rc,"native");
    if(!SCE_S_ISREG(st.st_mode))return wb_probe_failed(d,phase,"not-regular",WB_E_FORMAT,"predicate");
    if((uint64_t)st.st_size!=bytes)return wb_probe_failed(d,phase,"size",WB_E_PARTIAL,"predicate");
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);
    if(fd<0)return wb_probe_failed(d,phase,"open",fd,"native");
    size_t off=0;bool ok=true;
    while(off<bytes){
        int n=sceIoRead(fd,(uint8_t *)dst+off,(SceSize)(bytes-off));
        if(n<=0 || (size_t)n>bytes-off){
            ok=wb_probe_failed(d,phase,n<0?"read":n==0?"read-eof":"read-oversize",n,"native-return");break;
        }off+=(size_t)n;
    }
    uint8_t extra=0;
    if(ok){
        rc=sceIoRead(fd,&extra,1);
        if(rc!=0)ok=wb_probe_failed(d,phase,"trailing-read",rc,"native-return");
    }
    rc=sceIoClose(fd);
    if(rc<0)ok=wb_probe_failed(d,phase,"close",rc,"native");
    return ok;
}
static bool wb_probe_exact(const char *path,void *dst,size_t bytes) {
    return wb_probe_exact_d(path,dst,bytes,NULL,"exact-read");
}
static bool wb_probe_private_save(const wp_job *job) {
    SceSize needed=0;wp_job got={0};
    SceAppUtilSaveDataFile f={.filePath=WB_PROBE_PRIVATE_NAME,.buf=(void *)job,
        .bufSize=sizeof *job,.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    return sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&needed)==0 &&
        wb_probe_exact(WB_PROBE_PRIVATE_PATH,&got,sizeof got) && !memcmp(&got,job,sizeof got);
}
static bool wb_probe_clock_d(uint64_t *now,uint64_t *epoch,
        wb_probe_diagnostic *d,const char *phase) {
    SceRtcTick rtc={0};
    uint64_t t=(uint64_t)sceKernelGetSystemTimeWide();
    if(!t)return wb_probe_failed(d,phase,"system-time-zero",WB_E_STATE,"predicate");
    int rc=sceRtcGetCurrentTick(&rtc);
    if(rc!=0)return wb_probe_failed(d,phase,"rtc",rc,"native");
    if(rtc.tick<=t)return wb_probe_failed(d,phase,"rtc-before-system",WB_E_STATE,"predicate");
    *now=t;*epoch=rtc.tick-t;return true;
}
static bool wb_probe_clock(uint64_t *now,uint64_t *epoch) {
    return wb_probe_clock_d(now,epoch,NULL,"clock");
}
static bool wb_probe_live_d(const wp_job *j,uint64_t now,uint64_t epoch,
        wb_probe_diagnostic *d,const char *phase) {
    if(wp_job_live(j,now,epoch))return true;
    const char *why=!wp_job_shape(j)?"job-shape":now<j->issued_us?"before-issued":
                    now>=j->deadline_us?"deadline":"boot-epoch";
    return wb_probe_failed(d,phase,why,WB_E_STATE,"predicate");
}
static bool wb_probe_installed_d(wb_probe_diagnostic *d,const char *phase) {
    const wb_reg_entry *row=wb_reg_entry_for(WB_PROBE_TITLE,WB_PROBE_VERSION);
    if(!row)return wb_probe_failed(d,phase,"registry-missing",WB_E_TITLE,"predicate");
    if(row->cases[0])return wb_probe_failed(d,phase,"registry-cases",WB_E_FORMAT,"predicate");
    if(strcmp(row->sha256,WB_PROBE_VPK_SHA256))return wb_probe_failed(d,phase,"registry-sha",WB_E_SHA,"predicate");
    for(unsigned i=0;i<4;i++){
        if(d)d->member=(int)i;
        char path[112],actual[65];wb_vfile file;wb_reader rd;
        const int n=snprintf(path,sizeof path,"ux0:app/" WB_PROBE_TITLE "/%s",wb_probe_members[i].path);
        if(n<=0 || (size_t)n>=sizeof path)return wb_probe_failed(d,phase,"member-path",WB_E_PATH,"predicate");
        int rc=wb_vita_reader_open(path,&rd,&file);
        if(rc!=WB_OK)return wb_probe_failed(d,phase,"member-open",rc,"wb");
        bool ok=rd.size==wb_probe_members[i].bytes;
        if(!ok)(void)wb_probe_failed(d,phase,"member-size",WB_E_FORMAT,"predicate");
        wb_sha256 hash;wb_sha256_init(&hash);uint8_t buf[4096],digest[32];
        for(uint64_t off=0;ok && off<rd.size;){
            size_t take=rd.size-off>sizeof buf?sizeof buf:(size_t)(rd.size-off);
            rc=rd.read_at(rd.ctx,off,buf,take);
            if(rc!=WB_OK){ok=wb_probe_failed(d,phase,"member-read",rc,"wb");break;}
            wb_sha256_update(&hash,buf,take);off+=take;
        }
        wb_vita_reader_close(&file);
        if(!ok)return false;
        wb_sha256_final(&hash,digest);wb_sha_hex(digest,32,actual);
        if(strcmp(actual,wb_probe_members[i].sha256))return wb_probe_failed(d,phase,"member-sha",WB_E_SHA,"predicate");
    }
    if(d)d->member=-1;
    return true;
}
static bool wb_probe_installed(void) {
    return wb_probe_installed_d(NULL,"installed");
}
static bool wb_probe_remove_old(const char *path,const wp_job *old,bool known) {
    int exists=r1_exists(path);if(exists==0)return true;
    wp_job got={0};
    if(exists!=1 || !known || !wb_probe_exact(path,&got,sizeof got) || memcmp(&got,old,sizeof got))return false;
    return sceIoRemove(path)>=0;
}
static bool wb_probe_publish(const wp_job *job,wb_probe_diagnostic *d) {
    int rc=r1_exists(WP_JOB_PATH);
    if(rc!=0)return wb_probe_failed(d,"public-path","job-exists",rc,"exists-helper");
    rc=r1_exists(WB_PROBE_TEMP);
    if(rc!=0)return wb_probe_failed(d,"public-path","temp-exists",rc,"exists-helper");
    int fd=sceIoOpen(WB_PROBE_TEMP,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0600);
    if(fd<0)return wb_probe_failed(d,"public-open","open",fd,"native");
    size_t off=0;bool ok=true;
    while(off<sizeof *job){
        int n=sceIoWrite(fd,(const uint8_t *)job+off,(SceSize)(sizeof *job-off));
        if(n<=0 || (size_t)n>sizeof *job-off){
            ok=wb_probe_failed(d,"public-write",n<0?"write":n==0?"write-zero":"write-oversize",n,"native-return");break;
        }off+=(size_t)n;
    }
    if(ok){rc=sceIoSyncByFd(fd,0);if(rc<0)ok=wb_probe_failed(d,"public-sync","sync",rc,"native");}
    rc=sceIoClose(fd);
    if(rc<0)ok=wb_probe_failed(d,"public-close","close",rc,"native");
    wp_job got={0};
    if(ok && !wb_probe_exact_d(WB_PROBE_TEMP,&got,sizeof got,d,"public-readback"))ok=false;
    if(ok && memcmp(&got,job,sizeof got))ok=wb_probe_failed(d,"public-readback","content",WB_E_SHA,"predicate");
    if(!ok){(void)sceIoRemove(WB_PROBE_TEMP);return false;}
    /* No O_EXCL: it is unsupported by this Vita runtime. Serial paired shell,
     * fixed path, durable private pending and receiver claim limit collisions.
     * This is not a cross-title lock and does not grant any wake authority. */
    rc=r1_exists(WP_JOB_PATH);
    if(rc!=0)return wb_probe_failed(d,"public-rename","job-exists",rc,"exists-helper");
    rc=sceIoRename(WB_PROBE_TEMP,WP_JOB_PATH);
    if(rc<0)return wb_probe_failed(d,"public-rename","rename",rc,"native");
    if(!wb_probe_exact_d(WP_JOB_PATH,&got,sizeof got,d,"public-postverify"))return false;
    if(memcmp(&got,job,sizeof got))return wb_probe_failed(d,"public-postverify","content",WB_E_SHA,"predicate");
    return true;
}
static int wb_probe_err(wb_out *out,int *status,const char *why) {
    *status=1;return wb_out_printf(out,"ERR wake-probe %s; WB not closed\n",why);
}
static int wb_probe_diagnostic_err(wb_out *out,int *status,const wb_probe_diagnostic *d) {
    *status=1;
    return wb_out_printf(out,"ERR wake-probe phase=%s op=%s rc=0x%08X rc_kind=%s member=%d; WB not closed\n",
        d->phase,d->operation,(unsigned)d->rc,d->rc_kind,d->member);
}
static int wb_probe_status(wb_out *out,int *status) {
    *status=1;int exists=r1_exists(WB_PROBE_PRIVATE_PATH);
    if(exists==0){*status=0;return wb_out_puts(out,"wake-probe state=none readiness=not-provided\n");}
    wp_job j={0};wp_result r={0};uint64_t now=0,epoch=0;
    if(exists!=1 || !wb_probe_exact(WB_PROBE_PRIVATE_PATH,&j,sizeof j) || !wp_job_shape(&j))
        return wb_probe_err(out,status,"private-pending-invalid");
    if(!wb_probe_clock(&now,&epoch) || now<j.issued_us || !wp_epoch_valid(j.boot_epoch_us,epoch))
        return wb_probe_err(out,status,"INCONCLUSIVE clock-or-boot-fence");
    if(memcmp(j.source_run,a.run_hex,16))return wb_probe_err(out,status,"INCONCLUSIVE source-run-changed");
    if(!wb_probe_exact(WP_RESULT_PATH,&r,sizeof r) || !wp_result_matches(&r,&j))
        return wb_probe_err(out,status,"INCONCLUSIVE result-unavailable-or-mismatched");
    if(r.stage<WP_STAGE_VALIDATED || r.main_exit_intent>1 ||
       r.first_error_step>WP_E_WORKER || (!r.first_error_step && r.first_error_rc) ||
       r.main_started_us<j.issued_us || r.main_started_us>=j.deadline_us ||
       r.observed_us>now || r.observed_us<r.main_started_us ||
       (r.tick_count && r.last_tick_us<r.first_tick_us) ||
       (!r.tick_count && (r.first_tick_us || r.last_tick_us || r.max_gap_us)) ||
       (r.tick_count==1 && (r.first_tick_us!=r.last_tick_us || r.max_gap_us)) ||
       (r.tick_count>1 && (r.max_gap_us<WP_STEP_US ||
          r.max_gap_us>(r.last_tick_us-r.first_tick_us) ||
          r.max_gap_us<(r.last_tick_us-r.first_tick_us)/(r.tick_count-1)+
              ((r.last_tick_us-r.first_tick_us)%(r.tick_count-1)!=0))) ||
       (r.tick_count && (!r.arm_started_us || r.arm_started_us<r.main_started_us ||
          r.arm_started_us<j.issued_us || r.arm_started_us>=j.deadline_us ||
          r.first_tick_us<r.arm_started_us || r.last_tick_us<r.first_tick_us ||
          r.observed_us<r.last_tick_us || r.last_tick_us-r.arm_started_us>=WP_LEASE_US)))
        return wb_probe_err(out,status,"INCONCLUSIVE result-timeline-invalid");
    if(r.first_error_step || r.stage==WP_STAGE_FAILURE ||
       (r.bg_rc!=WP_RC_UNKNOWN && r.bg_rc!=0) ||
       (r.return_rc!=WP_RC_UNKNOWN && r.return_rc<0) ||
       (r.worker_exit_rc!=WP_RC_UNKNOWN && r.worker_exit_rc!=0))
        return wb_probe_err(out,status,"native-probe-failed; inspect result.bin");
    bool complete=r.stage==WP_STAGE_WORKER_STOP && r.tick_count==24 &&
        r.last_tick_us-r.first_tick_us>=WP_STEP_US*23 &&
        r.max_gap_us>=WP_STEP_US && r.max_gap_us<=UINT64_C(10000000) &&
        r.max_gap_us>=(r.last_tick_us-r.first_tick_us)/23+
            ((r.last_tick_us-r.first_tick_us)%23!=0) &&
        r.bg_rc==0 && r.return_rc==0 && r.main_exit_intent==1 && r.worker_exit_rc==0;
    if(!complete && now-j.issued_us>WP_JOB_TTL_US+WP_LEASE_US+UINT64_C(10000000))
        return wb_probe_err(out,status,"INCONCLUSIVE expired-incomplete-diagnostic");
    *status=0;
    return wb_out_printf(out,
        "wake-probe state=%s job=%.32s source=%.16s ticks=%u/24 max_gap_us=%" PRIu64 "\n"
        "wake-probe diagnostic=public-untrusted readiness=not-provided close_wb=disabled\n",
        complete?"DIAGNOSTIC_COMPLETE":"PENDING",j.job_id,j.source_run,r.tick_count,r.max_gap_us);
}
static int wb_probe_command(const wb_cmd *cmd,wb_out *out,int *status) {
    *status=1;
    if(!wb_standing_owner_pty() || !wb_ssh_connected(&g_ssh))return wb_probe_err(out,status,"no-paired-pty");
    if(cmd->force || cmd->no_reload || cmd->keep_stage || cmd->install_after ||
       cmd->no_period || cmd->promote_now || cmd->any_title || cmd->sha256[0])
        return wb_probe_err(out,status,"options-not-accepted");
    if(cmd->kind==WB_CMD_TERM_WAKE_PROBE_STATUS){
        if(cmd->argc!=0)return wb_probe_err(out,status,"status-usage");
        return wb_probe_status(out,status);
    }
    wp_job j={0};
    if(cmd->kind!=WB_CMD_TERM_WAKE_PROBE || cmd->argc!=1 || strlen(cmd->argv[0])>32)
        return wb_probe_err(out,status,"usage");
    memcpy(j.job_id,cmd->argv[0],strlen(cmd->argv[0])+1);
    if(!wp_job_id(j.job_id))return wb_probe_err(out,status,"job-id");
    /* r1_bound records a COMPLETED returned boot, not a live grant. Do not
     * block finite diagnostics after a legitimate update. Active source/armed
     * grants, pending queue and seal still exclude bootstrap. */
    if(r1_source_live || r1_signed_armed || r1_exists(WB_PENDING_PATH)!=0 ||
       r1_exists(WBQ_SEAL)!=0 || !private_link())return wb_probe_err(out,status,"busy-or-network");
    uint64_t now=0,epoch=0;
    if(!wb_probe_clock(&now,&epoch) || now>UINT64_MAX-WP_JOB_TTL_US)return wb_probe_err(out,status,"clock");
    wp_job old={0};int exists=r1_exists(WB_PROBE_PRIVATE_PATH);bool known=false;
    if(exists!=0){
        if(exists!=1 || !wb_probe_exact(WB_PROBE_PRIVATE_PATH,&old,sizeof old) || !wp_job_shape(&old))
            return wb_probe_err(out,status,"private-pending-invalid");
        known=true;
        if(wp_epoch_valid(old.boot_epoch_us,epoch) && (now<old.issued_us ||
           now-old.issued_us<WP_JOB_TTL_US+WP_LEASE_US+UINT64_C(10000000)))
            return wb_probe_err(out,status,"previous-probe-active");
    }
    if(!wb_probe_installed())return wb_probe_err(out,status,"installed-01.02-members-not-approved");
    if(wb_vita_mkdir_p(WB_PROBE_DIR)!=WB_OK ||
       !wb_probe_remove_old(WP_JOB_PATH,&old,known) ||
       !wb_probe_remove_old(WB_PROBE_TEMP,&old,known))return wb_probe_err(out,status,"job-path-collision");
    uint8_t random[16]={0};
    if(sceKernelGetRandomNumber(random,sizeof random)<0 || wp_zero(random,sizeof random))
        return wb_probe_err(out,status,"rng");
    char nonce[33];hex(nonce,random,sizeof random);memcpy(j.nonce,nonce,32);
    memcpy(j.source_run,a.run_hex,16);memcpy(j.magic,WP_JOB_MAGIC,8);
    j.version=WP_VERSION;j.bytes=sizeof j;j.issued_us=now;j.deadline_us=now+WP_JOB_TTL_US;j.boot_epoch_us=epoch;
    if(!wp_job_live(&j,now,epoch) || !wb_probe_private_save(&j))return wb_probe_err(out,status,"private-pending-save");
    wb_probe_diagnostic d={.member=-1};
    if(!wb_probe_installed_d(&d,"installed-recheck") ||
       !wb_probe_clock_d(&now,&epoch,&d,"publish-clock") ||
       !wb_probe_live_d(&j,now,epoch,&d,"publish-live") || !wb_probe_publish(&j,&d))
        return wb_probe_diagnostic_err(out,status,&d);
    if(!wb_probe_installed_d(&d,"final-installed") ||
       !wb_probe_clock_d(&now,&epoch,&d,"final-clock") ||
       !wb_probe_live_d(&j,now,epoch,&d,"final-live")){
        (void)wb_probe_remove_old(WP_JOB_PATH,&j,true);
        return wb_probe_diagnostic_err(out,status,&d);
    }
    if(!wb_standing_owner_pty() || !private_link() || r1_source_live ||
       r1_signed_armed || r1_exists(WB_PENDING_PATH)!=0 || r1_exists(WBQ_SEAL)!=0 ||
       !log_event("WAKE PROBE DISPATCH REQUEST; NOT RECEIVER READY")){
        (void)wb_probe_remove_old(WP_JOB_PATH,&j,true);
        return wb_probe_err(out,status,"final-admission-or-audit-failed");
    }
    /* Do not exit or pretend the background component exists yet. A gdc
     * bootstrap may suspend WB; actual platform return is an experiment. */
    a.guard_grace=now_ms()+15000;
    const int rc=sceAppMgrLaunchAppByUri(WB_HANDOFF_APP_URI,"psgm:play?titleid=" WB_PROBE_TITLE);
    if(rc<0){
        (void)wb_probe_remove_old(WP_JOB_PATH,&j,true);*status=1;
        return wb_out_printf(out,"ERR wake-probe bootstrap-launch-failed rc=0x%08X; WB not closed\n",(unsigned)rc);
    }
    *status=0;
    return wb_out_printf(out,"OK wake-probe DISPATCHED_UNVERIFIED job=%s nonce=%.32s source=%.16s rc=%d; no close authority\n",
        j.job_id,j.nonce,j.source_run,rc);
}
#endif
