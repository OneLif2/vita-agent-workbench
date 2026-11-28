#ifndef WB_CMD_H
#define WB_CMD_H

#include <stdbool.h>
#include <stddef.h>

enum { WB_CMD_MAX_ARGS = 6, WB_CMD_ARG_MAX = 128, WB_CMD_NAME_MAX = 24 };

typedef enum {
    WB_CMD_NONE = 0,
    WB_CMD_VER,
    WB_CMD_DF,
    WB_CMD_STATUS,
    WB_CMD_HELP,
    WB_CMD_INSTALL,
    WB_CMD_PUT,
    WB_CMD_GET,
    WB_CMD_RELOAD,
    WB_CMD_ROLLBACK,
    WB_CMD_PENDING,
    WB_CMD_PROMOTE,
    WB_CMD_INSPECT,
    WB_CMD_PLAN,
    WB_CMD_TIMELINE,
    WB_CMD_APP_INSTALL,
    WB_CMD_LAUNCH,
    WB_CMD_SHOT,
    WB_CMD_DEPLOY,
    WB_CMD_APPLY_CORE,
    WB_CMD_S1_CHECK,
    WB_CMD_BYE,
    WB_CMD_EXT,
    WB_CMD_HASH_SELFTEST,
    WB_CMD_R1_STATUS, WB_CMD_APPLY_RETURN, WB_CMD_PHOTO_EXPORT,
    /* Interactive terminal descriptors. No implicit raw-exec parser route. */
    WB_CMD_TERM_APP_LIST, WB_CMD_TERM_APP_PLAN, WB_CMD_TERM_RESULT, WB_CMD_TERM_DEPLOY,
    WB_CMD_TERM_FONT, WB_CMD_TERM_SSH_VITA_STATUS, WB_CMD_TERM_SSH_VITA_UNINSTALL,
    WB_CMD_TERM_USER_STATUS, WB_CMD_TERM_USER_PLAN, WB_CMD_TERM_USER_REMOVE,
    WB_CMD_TERM_UPDATER_CHECK, WB_CMD_TERM_CRASH_INDEX, WB_CMD_TERM_R1_REVIEW,
    WB_CMD_TERM_R1_NOTICE, WB_CMD_TERM_CLOSE_WB,
    WB_CMD_TERM_R1_SIGNED, WB_CMD_TERM_R1_AUTO_STATUS, WB_CMD_TERM_WB_STATUS,
    WB_CMD_TERM_WAKE_PROBE, WB_CMD_TERM_WAKE_PROBE_STATUS,
    WB_CMD_TERM_APP_APPROVE, WB_CMD_TERM_APP_RUNNING, WB_CMD_TERM_APP_PATCH,
    WB_CMD_TERM_DF_HUMAN, WB_CMD_TERM_LINUX, WB_CMD_TERM_AGENT_APP
} wb_cmd_kind;

typedef struct {
    wb_cmd_kind kind;
    char name[WB_CMD_NAME_MAX];
    int  argc;
    char argv[WB_CMD_MAX_ARGS][WB_CMD_ARG_MAX];
    bool force;
    bool no_reload;
    bool keep_stage;
    bool install_after;
    bool no_period;
    bool promote_now;
    bool any_title;
    char sha256[65];
} wb_cmd;

/* Parses one exec request. Returns false for a malformed line. */
bool wb_cmd_parse(const char *line, size_t len, wb_cmd *out);

const char *wb_cmd_help_text(void);
const char *wb_cmd_name(wb_cmd_kind kind);

#endif
