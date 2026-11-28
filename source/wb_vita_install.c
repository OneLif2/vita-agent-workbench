#include "wb_vita_install.h"

#include "wb_err.h"
#include "wb_vita_payload.h"
#include "wb_payload.h"
#include "startup.h"
#include "wb_str.h"
#include "wb_ver.h"

#include <psp2/appmgr.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/promoterutil.h>
#include <psp2/sysmodule.h>

#include <stdio.h>
#include <string.h>

/* Present in SceAppMgr_stub on this SDK but not in its appmgr.h, so the
 * prototypes are declared here. Both release the caller's content mounts for
 * the duration of the promote. */
int _sceAppMgrContentInstallPeriodStart(void);
int _sceAppMgrContentInstallPeriodStop(void);

/* ---- ScePromoterUtil plumbing, the same sequence VitaShell uses ---- */

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

#include "wb_paf_release.h"

static int promote_poll(void) {
    int state = 1;
    int result = 0;
    int state_rc = 0;
    for (unsigned i = 0; i < WB_INSTALL_MS / 50u; i++) {
        state_rc = scePromoterUtilityGetState(&state);
        if (state_rc < 0) break;
        if (!state) break;
        sceKernelDelayThread(50 * 1000);
    }
    startup_mark("PROMOTE POLL STATE", state);
    startup_mark("PROMOTE POLL RC", state_rc);
    if (state_rc < 0) return WB_E_PROMOTE;
    if (state) return WB_E_TIMEOUT;
    const int res_rc = scePromoterUtilityGetResult(&result);
    startup_mark("PROMOTE RESULT", result);
    startup_mark("PROMOTE RESULT RC", res_rc);
    if (res_rc < 0) return WB_E_PROMOTE;
    if (result != 0) return WB_E_PROMOTE;
    return WB_OK;
}

int wb_vita_promote_stage(const char *stage, bool skip_period, int *detail) {
    if (!stage) return WB_E_ARG;
    if (detail) *detail = 0;

    int rc = load_paf();
    startup_mark("PROMOTE PAF", rc);
    if (rc < 0) { if (detail) *detail = rc; return WB_E_PROMOTE; }

    rc = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    startup_mark("PROMOTE MODULE", rc);
    if (rc < 0) {
        if (detail) *detail = rc;
        (void)unload_paf();
        return WB_E_PROMOTE;
    }

    rc = scePromoterUtilityInit();
    startup_mark("PROMOTE INIT", rc);
    if (rc < 0) {
        if (detail) *detail = rc;
        (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
        (void)unload_paf();
        return WB_E_PROMOTE;
    }

    /* Release our own content mounts for the install window so the promoter
     * may rewrite ux0:app/INAP00018 while this process keeps running. */
    const int period = skip_period ? -1 : _sceAppMgrContentInstallPeriodStart();
    startup_mark("PROMOTE PERIOD", period);

    int async_rc = scePromoterUtilityPromotePkgWithRif(stage, 0);
    startup_mark("PROMOTE ASYNC", async_rc);
    int outcome;
    if (async_rc >= 0) {
        outcome = promote_poll();
    } else if (!strcmp(stage, WB_UPDATER_STAGE) || !strcmp(stage, WB_ROOT "/patch-0213")) {
        /* No retry of our fixed helper: a negative submission isn't proof
         * that no bubble was created. Reinspect on the next owner operation. */
        if (detail) *detail = async_rc;
        outcome = WB_E_PROMOTE;
    } else {
        /* A few firmwares dislike the async call for homebrew bubbles; retry
         * synchronously once before reporting failure. */
        if (detail) *detail = async_rc;
        const int sync_rc = scePromoterUtilityPromotePkgWithRif(stage, 1);
        startup_mark("PROMOTE SYNC", sync_rc);
        if (detail) *detail = sync_rc;
        outcome = sync_rc >= 0 ? WB_OK : WB_E_PROMOTE;
        if (sync_rc >= 0) outcome = promote_poll();
    }

    if (period >= 0) (void)_sceAppMgrContentInstallPeriodStop();

    (void)scePromoterUtilityExit();
    (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    (void)unload_paf();
    return outcome;
}

int wb_vita_delete_pkg(const char *title, int *detail) {
    if (!title || strlen(title) != 9) return WB_E_ARG;
    if (!strcmp(title, WB_TITLE_ID) || !strcmp(title, WB_UPDATER_TITLE_ID) || !strncmp(title, "NPXS", 4))
        return WB_E_PATH;
    if (detail) *detail = 0;
    char sys_path[64];
    snprintf(sys_path, sizeof sys_path, "vs0:/app/%.9s", title);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(sys_path, &st) >= 0) return WB_E_PATH;

    int rc = load_paf();
    if (rc < 0) { if (detail) *detail = rc; return WB_E_PROMOTE; }
    rc = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    if (rc < 0) { if (detail) *detail = rc; (void)unload_paf(); return WB_E_PROMOTE; }
    rc = scePromoterUtilityInit();
    if (rc < 0) {
        if (detail) *detail = rc;
        (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
        (void)unload_paf();
        return WB_E_PROMOTE;
    }
    int del_rc = scePromoterUtilityDeletePkg(title);
    int outcome = del_rc >= 0 ? promote_poll() : WB_E_PROMOTE;
    if (detail && del_rc < 0) *detail = del_rc;
    (void)scePromoterUtilityExit();
    (void)sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    (void)unload_paf();
    return outcome;
}

#include "wb_ssh_vita_uninstall.inc"
#include "wb_managed_app.inc"
#include "wb_updater_registration.inc"

/* ---- payload staging + live swap ---- */

static int copy_stage_entry(const char *entry, char *out, size_t cap) {
    char src[224];
    if (snprintf(src, sizeof src, "%s/%s", WB_STAGE_DIR, entry) >= (int)sizeof src) return WB_E_LIMIT;
    if (!wb_vita_exists(src)) return WB_E_IO;
    if (strlen(WB_PAYLOAD_NEW) >= cap) return WB_E_LIMIT;
    memcpy(out, WB_PAYLOAD_NEW, strlen(WB_PAYLOAD_NEW) + 1);
    return wb_vita_copy_file(src, out);
}

/* ---- backend glue ---- */

static int v_open(void *ctx, const char *path, wb_reader *rd) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    if (vi->vfile_open) { wb_vita_reader_close(&vi->vfile); vi->vfile_open = false; }
    const int rc = wb_vita_reader_open(path, rd, &vi->vfile);
    if (rc == WB_OK) vi->vfile_open = true;
    return rc;
}

static void v_close(void *ctx) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    if (vi->vfile_open) { wb_vita_reader_close(&vi->vfile); vi->vfile_open = false; }
}

static int v_reset(void *ctx) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    (void)wb_vita_remove_tree(WB_STAGE_DIR);
    const int rc = wb_vita_mkdir_p(WB_STAGE_DIR);
    if (rc == WB_OK) (void)wb_vita_writer_init(&vi->writer, WB_STAGE_DIR);
    return rc;
}

static const wb_writer *v_writer(void *ctx) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    return wb_vita_writer_ops(&vi->writer);
}

static int v_save_head(void *ctx, const uint8_t *head, size_t n) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    const wb_writer *w = wb_vita_writer_ops(&vi->writer);
    int rc = w->mkdirs(vi, "sce_sys/package");
    if (rc == WB_OK) rc = w->create(vi, "sce_sys/package/head.bin", n);
    if (rc == WB_OK) rc = w->write(vi, head, n);
    if (rc == WB_OK) rc = w->close(vi);
    return rc;
}

static int v_promote(void *ctx, const char *stage, bool skip_period) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    return wb_vita_promote_stage(stage, skip_period, &vi->promote_detail);
}

static int v_payload(void *ctx, const char *entry, char *version, size_t cap) {
    wb_vita_install *vi = (wb_vita_install *)ctx;
    (void)vi;
    char candidate[128];
    int rc = copy_stage_entry(entry, candidate, sizeof candidate);
    if (rc != WB_OK) return rc;
    return wb_vita_payload_swap(candidate, version, cap);
}

static const wb_inst_backend g_backend = {
    .open_vpk = v_open,
    .close_vpk = v_close,
    .stage_reset = v_reset,
    .writer = v_writer,
    .save_head = v_save_head,
    .promote = v_promote,
    .install_payload = v_payload,
    .say = NULL
};

const wb_inst_backend *wb_vita_install_backend(wb_vita_install *vi) {
    static wb_inst_backend backend;
    backend = g_backend;
    backend.ctx = vi;
    return &backend;
}
