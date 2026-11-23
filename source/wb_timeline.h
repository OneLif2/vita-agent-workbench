#ifndef WB_TIMELINE_H
#define WB_TIMELINE_H

#include "wb_out.h"

/* Upgrade timeline: one line per stage so the PC can tell "uploaded" from
 * "queued", "updater started" and "new core actually running".
 *
 * stage names: staged / queued / updater / verified / rolled-back / refused
 * File: ux0:data/INAP00018/timeline.txt (append, self-truncating). */

int wb_timeline_note(const char *stage, const char *version, const char *run);
unsigned wb_timeline_selftest(void);
int wb_timeline_dump(wb_out *out, unsigned max_lines);

#endif
