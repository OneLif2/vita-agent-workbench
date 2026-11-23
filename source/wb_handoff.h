#ifndef WB_HANDOFF_H
#define WB_HANDOFF_H

#include "wb_ver.h"
#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/rtc.h>
#include <stdio.h>

/* VitaSDK, sceAppMgrLaunchAppByUri: 0x20000 requests the application;
 * other values open LiveArea. Sony still owns any close/consent UI. */
enum { WB_HANDOFF_APP_URI = 0x20000 };

/* Observations only. Never derive a receipt/ticket or decide whether to
 * retry from this log. A returning syscall doesn't prove an app started. */
static inline void wb_handoff_note(const char *event, int rc) {
    SceRtcTick tick = {0};
    char line[160];
    int fd = sceIoOpen(WB_INSTALL_LOG, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0600);
    if (fd < 0) return;
    if (sceRtcGetCurrentTick(&tick) < 0) tick.tick = 0;
    int n = snprintf(line, sizeof line, "handoff source=%s rtc_us=%llu %s rc=0x%08X\n",
                     WB_VERSION, (unsigned long long)tick.tick, event, (unsigned)rc);
    if (n > 0 && (size_t)n < sizeof line) {
        (void)sceIoWrite(fd, line, (unsigned)n);
        (void)sceIoSyncByFd(fd, 0);
    }
    (void)sceIoClose(fd);
}

#endif
