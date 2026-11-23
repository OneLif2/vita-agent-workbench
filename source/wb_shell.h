#ifndef WB_SHELL_H
#define WB_SHELL_H
#include "wb_cmd.h"
#include "wb_out.h"
#include <stdbool.h>

enum { WB_SH_PATH = WB_CMD_ARG_MAX, WB_SH_LINE = 512 };
typedef struct { char cwd[WB_SH_PATH]; } wb_shell_engine;
/* All filesystem calls receive canonical display paths "ux0:/...". Runtime
 * adapter still enforces mount/name, file type, privacy, byte and time policy.
 * 0 success; positive means a reported, recoverable command error;
 * negative means the output channel failed. */
typedef struct {
    void *ctx;
    int (*isdir)(void *ctx,const char *absolute,wb_out *out);
    int (*list)(void *ctx,const char *absolute,bool long_format,wb_out *out);
    int (*cat)(void *ctx,const char *absolute,wb_out *out);
    int (*core_exec)(void *ctx,const wb_cmd *parsed,wb_out *out);
} wb_shell_ops;

void wb_shell_init(wb_shell_engine *sh);
int wb_shell_prompt(const wb_shell_engine *sh,wb_out *out);
/* Edit only the end of one PTY input line. No dispatch, no raw listing output.
 * Successful results are bounded printable text; caller provides WB_SH_LINE. */
bool wb_shell_complete(const wb_shell_engine *sh,const char *line,const wb_shell_ops *ops,char out[WB_SH_LINE]);
/* One NUL-terminated line: interactive transport rejects control bytes and
 * overlength input as a unit. Return 0 continue, 1 request closure, -1 fatal. */
int wb_shell_run(wb_shell_engine *sh,const char *line,wb_out *out,const wb_shell_ops *ops);
#endif
