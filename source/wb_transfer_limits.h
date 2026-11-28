#ifndef WB_TRANSFER_LIMITS_H
#define WB_TRANSFER_LIMITS_H
#include <stdint.h>
/* TTY/SFTP wire offsets and Vita transfer file sizes: full uint32 range.
 * Legacy WB_UPLOAD_MAX in wb_ver.h is retained solely for the frozen updater
 * provenance; it is not used as the active file-transfer policy anymore. */
#define WB_TRANSFER_MAX UINT64_C(0xffffffff)
#endif
