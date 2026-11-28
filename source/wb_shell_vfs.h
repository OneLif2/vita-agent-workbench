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
/* Only the explicit game Logs namespace; exact component/type checks before
 * opening SCE_O_RDONLY. Returns 0 with an owned fd, -1 with fd=-1 otherwise.
 * Never exposes another app directory, a symlink, or a writable descriptor. */
int wb_vita_shell_open_game_log(const char *canonical,int *fd);

#endif
