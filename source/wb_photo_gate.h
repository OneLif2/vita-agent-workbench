#ifndef WB_PHOTO_GATE_H
#define WB_PHOTO_GATE_H
#include "wb_out.h"
#include "wb_sftp_ro.h"

typedef int (*wb_photo_import)(const void *, size_t, int *cleanup_rc);
/* Every device operation after admission uses the read-only virtual root. 
 * status is the SSH exit status; the C return is the reply sink's result. */
int wb_photo_export_command(const char *path, const char *sha, wb_out *out, int *status,
                            const wb_sftp_ops *fs, wb_photo_import send_photo,
                            void *(*alloc)(size_t), int *cleanup_rc);
#endif
