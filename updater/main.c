/* Workbench Updater (INAP00019)
 *
 * A separate title whose only job is to promote the staged workbench core,
 * then start workbench again. This is the same shape as VitaShell's
 * VSUPDATER: the running app can never replace its own eboot, so a third
 * title does it while the target is stopped.
 *
 * Flow: workbench (INAP00018) installs this app, then starts it with
 * psgm:play. This process promotes ux0:data/INAP00018/stage/pkg and relaunches
 * INAP00018. Nothing here talks to the network. */

#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/promoterutil.h>
#include <psp2/rtc.h>
#include <psp2/sysmodule.h>

#include "../source/wbq_fixture.h"
#include "../source/wb_handoff.h"
#include "wb_return_commit.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STAGE_DIR       "ux0:data/INAP00018/stage/pkg"
#define LOG_PATH        "ux0:data/INAP00018/updater.log"

static void log_event(const char *what, int rc) {
    const int fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (fd < 0) return;
    char line[512];
    const int n = snprintf(line, sizeof line, "%s rc=0x%08X\n", what, (unsigned)rc);
    if (n > 0 && (size_t)n < sizeof line) (void)sceIoWrite(fd, line, (unsigned)n);
    (void)sceIoSyncByFd(fd, 0);
    (void)sceIoClose(fd);
}

static int load_paf(void) {
    static uint32_t argp[] = { 0x180000, (uint32_t)-1, (uint32_t)-1, 1, (uint32_t)-1, (uint32_t)-1 };
    int result = -1;
    uint32_t opt[4];
    opt[0] = sizeof opt;
    opt[1] = (uint32_t)(uintptr_t)&result;
    opt[2] = (uint32_t)-1;
    opt[3] = (uint32_t)-1;
    return sceSysmoduleLoadModuleInternalWithArg(SCE_SYSMODULE_INTERNAL_PAF, sizeof argp, argp,
                                                 (void *)opt);
}

#include "../source/wb_paf_release.h"

/* Only ever called with the updater-owned, enumerated and measured copy. */
static int native_handoff(const char *path,void *unused) {
    (void)unused;
    if(strcmp(path,WBQ_FINAL))return WB_E_PATH;
    int rc=scePromoterUtilityPromotePkgWithRif(path, 1);
    int result=-1;
    if (rc>=0) {
        int state=1,src=0;
        for (unsigned i=0;i<3000 && state;i++) {
            src=scePromoterUtilityGetState(&state);if(src<0 || !state)break;
            sceKernelDelayThread(100*1000);
        }
        if(src<0 || state || scePromoterUtilityGetResult(&result)<0)result=-1;
        log_event("result",result);
    }
    return rc<0?rc:result;
}
/* Same sequence as VitaShell's promoteApp(). */
static int promote_app(const wb_r1_ticket *intent) {
    int rc = load_paf();
    log_event("paf", rc);
    if (rc < 0) return rc;

    rc = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    log_event("promoter-module", rc);
    if (rc < 0) { (void)unload_paf(); return rc; }

    rc = scePromoterUtilityInit();
    log_event("promoter-init", rc);
    if (rc < 0) {
        (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
        (void)unload_paf();
        return rc;
    }

    char installed[6],completed[WBQ_CAP]={0};
    wq_begin("installed-identity");
    rc = wq_identity_file(WBQ_INSTALLED, installed);
    if (!rc) {
        const char *minimum=strcmp(installed,WB_VERSION)>0?installed:WB_VERSION;
        rc=wq_final_receipt(WB_PENDING_PATH,WBQ_SEAL,STAGE_DIR,WBQ_FINAL,minimum,native_handoff,NULL,completed);
        if(intent && !rc){
            SceRtcTick now={0};
            int accepted=WB_E_STATE;
            if(sceRtcGetCurrentTick(&now)>=0)
                accepted=wru_complete(intent,now.tick,installed,completed,rc);
            /* Promotion is independent. Failed optional proof means manual startup. */
            log_event("r1-return-proof",accepted);
        }
    }
    log_event("wbq2-final-handoff",rc);
    if(rc && wq_last.op){char detail[384];(void)wq_diag_format(detail,sizeof detail,&wq_last);log_event(detail,rc);}
    (void)scePromoterUtilityExit();
    (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    (void)unload_paf();
    return rc;
}

/* The core writes this before starting us, but the platform kills the core
 * immediately afterwards; a copy written here (with sync) is the one that
 * survives. The version comes from the receipt that is still on disk. */
static void write_return_intent(void) {
    char receipt[64];
    size_t n = 0;
    if (wq_read(WB_PENDING_PATH, receipt, sizeof receipt - 1, &n) != 0 || n < 10) return;
    receipt[n] = 0;
    if (strncmp(receipt, "WBQ2 ", 5)) return;
    char ver[6] = {0};
    memcpy(ver, receipt + 5, 5);
    SceRtcTick tick;
    if (sceRtcGetCurrentTick(&tick) < 0 || !tick.tick) return;
    char body[64];
    const int len = snprintf(body, sizeof body, "build=%s\nissued=%llu\n",
                             ver, (unsigned long long)tick.tick);
    if (len <= 0) return;
    const int fd = sceIoOpen(WB_ROOT "/return-intent.txt",
                             SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (fd < 0) { log_event("return-intent-open", fd); return; }
    const int w = sceIoWrite(fd, body, (SceSize)len);
    (void)sceIoSyncByFd(fd, 0);
    (void)sceIoClose(fd);
    log_event("return-intent", w == len ? 0 : w);
}

static int launch_workbench(void) {
    wb_handoff_note("updater->core request", 0);
    int rc = sceAppMgrLaunchAppByUri(WB_HANDOFF_APP_URI, "psgm:play?titleid=" WB_TITLE_ID);
    wb_handoff_note("updater->core reply", rc);
    return rc;
}

int main(void) {
    log_event("enter", 0);
    wb_handoff_note("updater entry", 0);
    int prepare_rc = sceAppMgrDestroyOtherApp();
    wb_handoff_note("updater destroy-other reply", prepare_rc);

    wb_r1_ticket intent={0};
    bool have=wru_take(&intent);
    SceIoStat req;memset(&req,0,sizeof req);
    int self=sceIoGetstat(WBQ_TEST,&req);
    if (self>=0) {
        char token[17]={0},log[1024]={0};size_t n=0;
        int rc=wq_read(WBQ_TEST,token,16,&n);
        if(sceIoRemove(WBQ_TEST)<0 || rc || n!=16 || strspn(token,"0123456789ABCDEF")!=16)
            rc=WB_E_FORMAT;
        else rc=wq_fx_run(token,log,sizeof log);
        if(log[0]) (void)wq_save(WB_ROOT "/s1-selfcheck.txt",log,strlen(log));
        log_event("isolated-final-verifier-selfcheck",rc);
    } else {
        int rc=promote_app(have && (uint32_t)self==UINT32_C(0x80010002)?&intent:NULL);
        log_event("promote-final",rc);
        if(rc==0){write_return_intent();(void)sceIoRemove(WB_PENDING_PATH);(void)sceIoRemove(WBQ_SEAL);}
        else {
            log_event("refused-retained-queue",rc);
            const char line[]="stage=refused ver=- run=INAP00019 reason=wbq2-or-promote-failed\n";
            int fd=sceIoOpen(WB_ROOT "/updater-refusal.log",SCE_O_WRONLY|SCE_O_CREAT|SCE_O_APPEND,WQ_FILE_MODE);
            if(fd>=0){(void)wq_write(fd,line,sizeof line-1);(void)sceIoSyncByFd(fd,0);(void)sceIoClose(fd);}
        }
    }
    const int lrc = launch_workbench();
    if(lrc<0)(void)wru_drop(WB_R1_SUCCESS);
    log_event("launch", lrc);
    sceKernelExitProcess(0);
    return 0;
}
