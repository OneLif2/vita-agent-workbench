#ifndef WB_VITA_PAYLOAD_H
#define WB_VITA_PAYLOAD_H

#include <stdbool.h>
#include <stddef.h>

#include "wb_payload.h"

/* Loads the payload that should be live at boot: ux0 payload first, the copy
 * shipped inside the vpk second. */
int wb_vita_payload_boot(char *version, size_t cap);

/* Live swap: unload the running payload, install candidate as current and
 * start it. On failure the previous payload is restored and the error is
 * returned; the SSH session is untouched either way. */
int wb_vita_payload_swap(const char *candidate, char *version, size_t cap);
int wb_vita_payload_reload_previous(char *version, size_t cap);

const wb_payload_v1 *wb_vita_payload_table(void);
const char *wb_vita_payload_version(void);
void wb_vita_payload_unload(void);

/* Last load attempt, for the startup log: the SceUID returned by the loader,
 * the loader status word, and what module_start wrote back. */
typedef struct {
    int load_rc;
    int load_status;
    unsigned boot_magic;
    int table;
    unsigned seen_args;
    unsigned seen_magic;
    unsigned seen_abi;
    unsigned payload_result;
} wb_payload_diag;
void wb_vita_payload_diag(wb_payload_diag *out);

#endif
