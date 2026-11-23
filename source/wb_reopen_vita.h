#ifndef WB_REOPEN_VITA_H
#define WB_REOPEN_VITA_H
/* Leave a clean run after a successful update.
 *
 * A signed update is granted on one run and produces a run that boots from the
 * return proof; `wb_standing_issue` refuses while `r1_bound` is set, so that run
 * cannot grant the next update. `r1_bound` is in-memory: a fresh process starts
 * with `r1_bound == false` and the proof files are already consumed, so one
 * self-restart turns "returned" into "none".
 *
 * Restarting an app without the owner asking is not something to do on a guess,
 * so the *host* states the intent by leaving a marker in its own upload root
 * before it applies. The marker lives outside the app's private directory, it is
 * read once, removed immediately, and never re-created by the device.
 */
#include <stdbool.h>
#include <psp2/appmgr.h>

#include "wb_vita_io.h"

/* Host-created, device-consumed. Empty file; existence is the whole signal. */
#define WB_REOPEN_MARKER "ux0:/VITA-POC/r1-reopen.once"

static bool wb_reopen_requested(void) {
    return wb_vita_exists(WB_REOPEN_MARKER);
}

/* One restart, then the daemon is gone: never loop, never retry on failure.
 * `app0:eboot.bin` is this application's own path inside the VPK mount. */
static bool wb_reopen_self(void) {
    static char arg0[] = "eboot.bin";
    static char *argv[] = { arg0, NULL };
    return sceAppMgrLoadExec("app0:eboot.bin", argv, NULL) == 0;
}
#endif
