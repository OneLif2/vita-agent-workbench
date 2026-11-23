/* Finite no-network BG canary. Only private matching generation may tick. */
#include "life.h"
#include "probe_io.h"
#include <psp2/kernel/threadmgr.h>
static int failed(wp_result*r,uint32_t step,int rc){wp_error(r,step,rc);r->worker_exit_rc=rc;(void)wp_private_put(WP_WORKER_ERROR_NAME,r,sizeof *r);(void)wp_publish(r);return 2;}
static int await_final_main(const wp_job*job,uint64_t start,wp_result*r){
    int last=WP_BAD_STATE;
    for(unsigned attempt=0;attempt<30;attempt++){
        uint64_t now=0,epoch=0;int rc=wp_clock(&now,&epoch);
        if(rc||!wp_epoch_valid(job->boot_epoch_us,epoch))return failed(r,WP_E_CLOCK,rc?rc:WP_BAD_CLOCK);
        wp_job claimed;rc=wp_load_claim(&claimed);
        if(rc||memcmp(&claimed,job,sizeof *job))return failed(r,WP_E_CLAIM,rc?rc:WP_BAD_JOB);
        lc_arm current;rc=lc_load_arm(&current);
        if(rc||current.start!=start||!lc_live(&current,now))return failed(r,WP_E_ARM,rc?rc:WP_BAD_STATE);
        wp_result observed;rc=wp_load_main(&observed);
        if(!rc){
            if(!wp_result_matches(&observed,job)||observed.arm_started_us!=start)return failed(r,WP_E_RECEIPT,WP_BAD_STATE);
            *r=observed;
            if(r->bg_rc!=WP_RC_UNKNOWN&&r->main_exit_intent==1&&r->return_rc!=WP_RC_UNKNOWN)return 0;
            last=WP_BAD_STATE;
        }else last=rc;
        /* Only this own receipt may be transient during its one final commit.
         * Claim, arm generation and clock changes are never retried. */
        rc=sceKernelDelayThread(100000);if(rc)return failed(r,WP_E_RECEIPT,rc);
    }
    return failed(r,WP_E_RECEIPT,last);
}
int main(void){
    if(lc_init())return 2;
    wp_job job={0};if(wp_load_claim(&job)||!wp_job_shape(&job))return 3;
    wp_result r;wp_result_init(&r,&job);r.stage=WP_STAGE_VALIDATED;
    lc_arm arm={0};lc_trace trace={0};uint64_t now=0,epoch=0;
    int rc=wp_clock(&now,&epoch);if(rc||!wp_epoch_valid(job.boot_epoch_us,epoch))return failed(&r,WP_E_CLOCK,rc?rc:WP_BAD_CLOCK);
    rc=lc_load_arm(&arm);if(rc)return failed(&r,WP_E_ARM,rc);
    rc=lc_load_trace(&trace);if(rc)return failed(&r,WP_E_TRACE,rc);
    if(!lc_live(&arm,now)||!lc_valid(&trace)||trace.start!=arm.start||trace.count||arm.start<job.issued_us||arm.start>=job.deadline_us)return failed(&r,WP_E_WORKER,WP_BAD_STATE);
    r.arm_started_us=arm.start;if(await_final_main(&job,arm.start,&r))return 2;
    for(unsigned i=0;i<LC_CAP;i++){
        wp_job claim={0};wp_result main_status;lc_arm current={0};
        rc=wp_clock(&now,&epoch);if(rc||!wp_epoch_valid(job.boot_epoch_us,epoch))return failed(&r,WP_E_CLOCK,rc?rc:WP_BAD_CLOCK);
        rc=wp_load_claim(&claim);if(rc||memcmp(&claim,&job,sizeof job))return failed(&r,WP_E_CLAIM,rc?rc:WP_BAD_JOB);
        rc=wp_load_main(&main_status);if(rc||!wp_result_matches(&main_status,&job)||main_status.arm_started_us!=arm.start)return failed(&r,WP_E_RECEIPT,rc?rc:WP_BAD_STATE);
        r=main_status;
        /* A new main receipt has no worker counters: preserve committed trace
         * progress even on a later revoke/generation/error before next tick. */
        r.observed_us=now;r.tick_count=trace.count;
        if(trace.count){r.first_tick_us=trace.us[0];r.last_tick_us=trace.us[trace.count-1];r.max_gap_us=0;
            for(unsigned k=1;k<trace.count;k++)if(trace.us[k]-trace.us[k-1]>r.max_gap_us)r.max_gap_us=trace.us[k]-trace.us[k-1];}
        rc=lc_load_arm(&current);if(rc)return failed(&r,WP_E_ARM,rc);
        if(!current.enabled)break;
        if(current.start!=arm.start||!lc_tick(&current,&trace,now))return failed(&r,WP_E_WORKER,WP_BAD_STATE);
        rc=lc_save_trace(&trace);if(rc)return failed(&r,WP_E_TRACE,rc);
        r.observed_us=now;r.arm_started_us=arm.start;r.tick_count=trace.count;r.first_tick_us=trace.us[0];r.last_tick_us=trace.us[trace.count-1];r.max_gap_us=0;
        for(unsigned k=1;k<trace.count;k++)if(trace.us[k]-trace.us[k-1]>r.max_gap_us)r.max_gap_us=trace.us[k]-trace.us[k-1];
        if(!r.first_error_step)r.stage=WP_STAGE_WORKER_TICK;
        rc=wp_publish(&r);if(rc)return failed(&r,WP_E_PUBLIC,rc);
        if(i+1<LC_CAP){rc=sceKernelDelayThread(5000000);if(rc)return failed(&r,WP_E_WORKER,rc);}
    }
    if(!r.first_error_step){r.stage=WP_STAGE_WORKER_STOP;}
    r.worker_exit_rc=0;
    rc=wp_publish(&r);if(rc)return failed(&r,WP_E_PUBLIC,rc);
    return 0;
}
