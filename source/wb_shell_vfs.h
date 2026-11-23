#ifndef WB_SHELL_VFS_H
#define WB_SHELL_VFS_H
#include <stdbool.h>
#include "wb_out.h"

/* Absolute shell namespace, not the host PC filesystem. Native OS calls are
 * read-only. The engine resolves cwd/. /.. before calling these methods.
 * 0: success, 1: ERR emitted, -1: shell output failed. */
int wb_vita_shell_isdir(void *ctx,const char *canonical,wb_out *out);
int wb_vita_shell_list(void *ctx,const char *canonical,bool longfmt,wb_out *out);
int wb_vita_shell_cat(void *ctx,const char *canonical,wb_out *out);

#endif
