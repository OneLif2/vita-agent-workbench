#ifndef WB_PAYLOAD_H
#define WB_PAYLOAD_H

#include <stdbool.h>
#include <stdint.h>

#include "wb_out.h"

/* The live-updatable half of workbench. The core keeps the SSH transport and
 * the installer; everything that changes between releases lives in this
 * module and is swapped in place, so the owner's SSH connection never drops. */
#define WB_PAYLOAD_MAGIC 0x31425750u /* "PWB1" little endian */
#define WB_BOOT_MAGIC    0x314f4257u /* "WBO1" */

typedef struct wb_payload_v1 {
    uint32_t magic;
    uint32_t abi;
    uint32_t size;
    const char *version;   /* "01.10-p1" */
    const char *build;     /* build tag or date */
    const char *features;  /* space separated capability list */
    int (*dispatch)(const char *cmd, int argc, char *const argv[], wb_out *out, void *core);
} wb_payload_v1;

/* Passed to the payload's module_start; the payload writes its table back. */
typedef struct wb_payload_boot {
    uint32_t magic;
    uint32_t abi;
    uint32_t size;
    const wb_payload_v1 *table;
    /* Filled by module_start so the core can tell "never called" from
     * "called and rejected". */
    uint32_t seen_args;
    uint32_t seen_magic;
    uint32_t seen_abi;
    uint32_t result;
} wb_payload_boot;

bool wb_payload_ok(const wb_payload_v1 *table);

#endif
