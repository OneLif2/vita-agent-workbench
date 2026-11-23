#ifndef WB_UPDATER_H
#define WB_UPDATER_H

#include <stdbool.h>

/* Workbench Updater (INAP00019): a separate title that promotes the staged
 * workbench core and restarts it. Copied from VitaShell's VSUPDATER flow, the
 * only way to replace an eboot whose process is running. */

bool wb_updater_available(void);
int  wb_updater_probe(int *detail);     /* read-only: 0 absent, 1 exact reusable pair on WB_OK */
const char *wb_updater_decision(void);  /* constant description of last probe or preparation */
int  wb_updater_install(int *detail);   /* ensure: 0 freshly installed, 1 reused on WB_OK */
int  wb_updater_launch(void);           /* psgm:play?titleid=INAP00019 */

#endif
