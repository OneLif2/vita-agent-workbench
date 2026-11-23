/* Headless, finite owner-PTY job bridge. No network, input injection or receiver.
 * Public job/result bytes are diagnostic correlation, never update/close authority. */
#include "life.h"
#include "probe_io.h"
#include <psp2/bgapputil.h>
#include <psp2/sysmodule.h>
#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/processmgr.h>
#include <string.h>
static int publish_before_worker(wp_result*r){int rc=wp_save_main(r);if(rc){wp_error(r,WP_E_RECEIPT,rc);return rc;}rc=wp_publish(r);if(rc)wp_error(r,WP_E_PUBLIC,rc);return rc;}
static void revoke_arm(uint64_t start){lc_arm a={0};if(start&&!lc_load_arm(&a)&&a.magic==LC_MAGIC&&a.enabled==1&&a.start==start){a.enabled=0;(void)lc_save_arm(&a);}}
static int return_wb(wp_result*r,int worker_started){
    r->main_exit_intent=1;if(!r->first_error_step)r->stage=WP_STAGE_RETURN_REQUEST;
    int rc=0;
    /* Fixed title only. A request rc is not proof of a new Workbench run. */
    r->return_rc=sceAppMgrLaunchAppByUri(0x20000,"psgm:play?titleid=INAP00018");
    if(r->return_rc<0)wp_error(r,WP_E_RETURN,r->return_rc);
    rc=wp_save_main(r);if(rc)wp_error(r,WP_E_RECEIPT,rc);
    if(!worker_started)(void)wp_publish(r);
    int status=r->first_error_step?2:0;
    (void)sceKernelExitProcess(status);return status;
}
int main(void){
    int rc=lc_init();if(rc)return 2; /* Cannot safely inspect a private claim. */
    wp_job job={0};if(wp_read_exact(WP_JOB_PATH,&job,sizeof job))return 3;
    uint64_t now=0,epoch=0;rc=wp_clock(&now,&epoch);if(rc||!wp_job_live(&job,now,epoch))return 3;
    int own_arm=0;wp_result r;wp_result_init(&r,&job);r.stage=WP_STAGE_VALIDATED;r.main_started_us=r.observed_us=now;
    lc_arm old={0};rc=lc_load_arm(&old);
    if(!rc){if(old.magic!=LC_MAGIC||old.enabled>1||!old.start||now<old.start){return 3;}if(lc_live(&old,now)){return 3;}}
    else if(!wp_missing(rc)){return 3;}
    wp_job previous={0};rc=wp_load_claim(&previous);
    if(!rc){if(!wp_job_shape(&previous)){return 3;}if(!memcmp(previous.nonce,job.nonce,32)){return 3;}}
    else if(!wp_missing(rc)){wp_error(&r,WP_E_CLAIM,rc);goto fail;}
    /* Re-read the exact job before private one-shot claim. The paired WB bridge
     * serializes job publication; neither public path can confer authority. */
    wp_job check={0};rc=wp_read_exact(WP_JOB_PATH,&check,sizeof check);
    if(rc||memcmp(&check,&job,sizeof job)){wp_error(&r,WP_E_JOB_READ,rc?rc:WP_BAD_JOB);goto fail;}
    rc=wp_save_claim(&job);if(rc){wp_error(&r,WP_E_CLAIM,rc);goto fail;}
    rc=wp_read_exact(WP_JOB_PATH,&check,sizeof check);
    if(rc||memcmp(&check,&job,sizeof job)){wp_error(&r,WP_E_CONSUME,rc?rc:WP_BAD_JOB);goto fail;}
    rc=sceIoRemove(WP_JOB_PATH);if(rc){wp_error(&r,WP_E_CONSUME,rc);goto fail;}
    r.stage=WP_STAGE_CLAIMED;if(publish_before_worker(&r))goto fail;
    rc=wp_clock(&now,&epoch);if(rc||!wp_job_live(&job,now,epoch)){wp_error(&r,WP_E_CLOCK,rc?rc:WP_BAD_CLOCK);goto fail;}
    lc_arm arm={LC_MAGIC,1,now};lc_trace trace={.magic=LC_TRACE,.count=0,.start=now};r.arm_started_us=now;
    rc=lc_save_trace(&trace);if(rc){wp_error(&r,WP_E_TRACE,rc);goto fail;}
    own_arm=1;rc=lc_save_arm(&arm);if(rc){wp_error(&r,WP_E_ARM,rc);goto fail;}
    r.stage=WP_STAGE_ARMED;if(publish_before_worker(&r))goto fail;
    rc=sceSysmoduleLoadModule(SCE_SYSMODULE_BG_APP_UTIL);if(rc){wp_error(&r,WP_E_BG_MODULE,rc);goto fail;}
    rc=wp_clock(&now,&epoch);
    if(rc||!wp_job_live(&job,now,epoch)||!lc_live(&arm,now)){wp_error(&r,WP_E_CLOCK,rc?rc:WP_BAD_CLOCK);goto fail;}
    r.stage=WP_STAGE_BG_REQUEST;r.bg_rc=sceBgAppUtilStartBgApp(1);
    if(r.bg_rc){wp_error(&r,WP_E_BG_START,r.bg_rc);goto fail;}
    /* Worker owns public result after this point. Private main receipt records
     * BG/return actual RCs; worker merges it on each bounded tick. */
    return return_wb(&r,1);
fail:
    if(own_arm){revoke_arm(r.arm_started_us);}
    (void)wp_save_main(&r);(void)wp_publish(&r);return return_wb(&r,0);
}
