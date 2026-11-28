#include "wb_cmd.h"

#include "wb_str.h"
#include "wb_ver.h"

#include <string.h>

static char lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

static bool eq(const char *a, const char *b) {
    while (*a && lc(*a) == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

const char *wb_cmd_name(wb_cmd_kind kind) {
    switch (kind) {
        case WB_CMD_DF:         return "df";
        case WB_CMD_VER:        return "ver";
        case WB_CMD_STATUS:     return "status";
        case WB_CMD_HELP:       return "help";
        case WB_CMD_INSTALL:    return "install";
        case WB_CMD_PUT:        return "put";
        case WB_CMD_GET:        return "get";
        case WB_CMD_PHOTO_EXPORT: return "photo-export";
        case WB_CMD_RELOAD:     return "reload";
        case WB_CMD_ROLLBACK:   return "rollback";
        case WB_CMD_PROMOTE:    return "promote";
        case WB_CMD_INSPECT:    return "inspect";
        case WB_CMD_R1_STATUS: return "r1-status";
        case WB_CMD_TERM_R1_REVIEW: return "r1-review";
        case WB_CMD_TERM_R1_NOTICE: return "r1-notice";
        case WB_CMD_TERM_R1_SIGNED: return "r1-signed";
        case WB_CMD_TERM_R1_AUTO_STATUS: return "r1-auto-status";
        case WB_CMD_TERM_WB_STATUS: return "wb-status";
        case WB_CMD_TERM_WAKE_PROBE: return "wake-probe";
        case WB_CMD_TERM_WAKE_PROBE_STATUS: return "wake-probe-status";
        case WB_CMD_TERM_APP_RUNNING: return "app-running";
        case WB_CMD_TERM_CLOSE_WB: return "close-wb";
        case WB_CMD_TERM_UPDATER_CHECK: return "updater-check";
        case WB_CMD_TERM_CRASH_INDEX: return "crash-index";
        case WB_CMD_APPLY_RETURN: return "apply-return";
        case WB_CMD_HASH_SELFTEST: return "hash-selftest";
        case WB_CMD_PLAN:       return "plan";
        case WB_CMD_TIMELINE:   return "timeline";
        case WB_CMD_APP_INSTALL: return "app-install";
        case WB_CMD_TERM_APP_APPROVE: return "app-approve";
        case WB_CMD_LAUNCH:     return "launch";
        case WB_CMD_SHOT:       return "shot";
        case WB_CMD_DEPLOY:     return "deploy";
        case WB_CMD_PENDING:    return "pending";
        case WB_CMD_S1_CHECK: return "s1-check";
        case WB_CMD_APPLY_CORE: return "apply-core";
        case WB_CMD_TERM_LINUX: return "linux";
        case WB_CMD_TERM_AGENT_APP: return "agent-app";
        case WB_CMD_BYE:        return "bye";
        case WB_CMD_EXT:        return "ext";
        default:                return "none";
    }
}

static bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

bool wb_cmd_parse(const char *line, size_t len, wb_cmd *out) {
    if (!line || !out || len == 0 || len > 1024) return false;
    memset(out, 0, sizeof *out);

    size_t i = 0;
    while (i < len && is_space(line[i])) i++;
    if (i == len) return false;

    /* command word */
    size_t n = 0;
    while (i < len && !is_space(line[i])) {
        if (n + 1 >= sizeof out->name) return false;
        out->name[n++] = line[i++];
    }
    out->name[n] = 0;
    for (size_t k = 0; k < n; k++) out->name[k] = lc(out->name[k]);

    /* operands and options */
    while (i < len) {
        while (i < len && is_space(line[i])) i++;
        if (i == len) break;
        size_t s = i;
        while (i < len && !is_space(line[i])) i++;
        const size_t tlen = i - s;
        if (tlen == 0) continue;
        char token[WB_CMD_ARG_MAX];
        if (tlen >= sizeof token) return false;
        memcpy(token, line + s, tlen);
        token[tlen] = 0;

        if (token[0] == '-' && token[1] == '-') {
            if (eq(token, "--force")) out->force = true;
            else if (eq(token, "--no-reload")) out->no_reload = true;
            else if (eq(token, "--keep-stage")) out->keep_stage = true;
            else if (eq(token, "--install")) out->install_after = true;
            else if (eq(token, "--no-period")) out->no_period = true;
            else if (eq(token, "--promote-now")) out->promote_now = true;
            else if (eq(token, "--any-title")) out->any_title = true;
            else return false;
            continue;
        }
        if (!strncmp(token, "sha256=", 7)) {
            if (strlen(token + 7) != 64) return false;
            memcpy(out->sha256, token + 7, 65);
            continue;
        }
        if (out->argc >= WB_CMD_MAX_ARGS) return false;
        memcpy(out->argv[out->argc], token, tlen + 1);
        out->argc++;
    }

    if (eq(out->name, "ver") || eq(out->name, "version")) out->kind = WB_CMD_VER;
    else if (eq(out->name, "df")) out->kind = WB_CMD_DF;
    else if (eq(out->name, "status")) out->kind = WB_CMD_STATUS;
    else if (eq(out->name, "help") || eq(out->name, "?")) out->kind = WB_CMD_HELP;
    else if (eq(out->name, "install")) out->kind = WB_CMD_INSTALL;
    else if (eq(out->name, "put")) out->kind = WB_CMD_PUT;
    else if (eq(out->name, "get")) out->kind = WB_CMD_GET;
    else if (eq(out->name, "photo-export")) out->kind = WB_CMD_PHOTO_EXPORT;
    else if (eq(out->name, "reload")) out->kind = WB_CMD_RELOAD;
    else if (eq(out->name, "rollback")) out->kind = WB_CMD_ROLLBACK;
    else if (eq(out->name, "promote")) out->kind = WB_CMD_PROMOTE;
    else if (eq(out->name, "inspect")) out->kind = WB_CMD_INSPECT;
    else if (eq(out->name, "hash-selftest")) out->kind = WB_CMD_HASH_SELFTEST;
    else if (eq(out->name, "plan")) out->kind = WB_CMD_PLAN;
    else if (eq(out->name, "timeline")) out->kind = WB_CMD_TIMELINE;
    else if (eq(out->name, "app-install")) out->kind = WB_CMD_APP_INSTALL;
    else if (eq(out->name, "launch")) out->kind = WB_CMD_LAUNCH;
    else if (eq(out->name, "shot")) out->kind = WB_CMD_SHOT;
    else if (eq(out->name, "deploy")) out->kind = WB_CMD_DEPLOY;
    else if (eq(out->name, "pending")) out->kind = WB_CMD_PENDING;
    else if (eq(out->name, "r1-status")) out->kind = WB_CMD_R1_STATUS;
    else if (eq(out->name, "apply-return")) out->kind = WB_CMD_APPLY_RETURN;
    else if (eq(out->name, "s1-check")) out->kind = WB_CMD_S1_CHECK;
    else if (eq(out->name, "apply-core")) out->kind = WB_CMD_APPLY_CORE;
    else if (eq(out->name, "close") || eq(out->name,"r1-signed") || eq(out->name,"r1-auto-status") ||
             eq(out->name,"wb-status") || eq(out->name,"wb") || eq(out->name,"wake") ||
             eq(out->name,"ps") || eq(out->name,"app"))
        return false; /* fixed paired-PTY commands, never payload/exec */
    else if (eq(out->name, "bye") || eq(out->name, "exit") || eq(out->name, "quit"))
        out->kind = WB_CMD_BYE;
    else out->kind = WB_CMD_EXT;

    switch (out->kind) {
        case WB_CMD_PHOTO_EXPORT:
            /* No generic flags or optional sha256= token on this explicit operation. */
            return !out->force && !out->no_reload && !out->keep_stage && !out->install_after &&
                !out->no_period && !out->promote_now && !out->any_title && !out->sha256[0] &&
                out->argc==2 && strlen(out->argv[1])==64 &&
                strspn(out->argv[1],"0123456789abcdef")==64 && !memchr(line,0,len);
        case WB_CMD_R1_STATUS:
        case WB_CMD_APPLY_RETURN:
            /* No options, ignored operands or SHA parameters on the consent interface. */
            if(out->force || out->no_reload || out->keep_stage || out->install_after || out->no_period ||
               out->promote_now || out->any_title || out->sha256[0])return false;
            if(out->kind==WB_CMD_R1_STATUS)return out->argc==0;
            return out->argc==1 && strlen(out->argv[0])==32 && strspn(out->argv[0],"0123456789ABCDEF")==32;
        case WB_CMD_INSTALL:
        case WB_CMD_GET:
        case WB_CMD_INSPECT:
        case WB_CMD_DEPLOY:
            if (out->argc != 1) return false;
            break;
        case WB_CMD_HASH_SELFTEST:
        case WB_CMD_SHOT:
            if (out->argc != 0) return false;
            break;
        case WB_CMD_TIMELINE:
            if (out->argc && (out->argc!=1 || !eq(out->argv[0],"selftest"))) return false;
            break;
        case WB_CMD_LAUNCH:
            if (out->argc != 3) return false;
            break;
        case WB_CMD_PUT:
            if (out->argc != 2) return false;
            break;
        case WB_CMD_DF:
            if (out->argc > 1) return false;
            break;
        case WB_CMD_RELOAD:
        case WB_CMD_ROLLBACK:
        case WB_CMD_VER:
        case WB_CMD_STATUS:
        case WB_CMD_HELP:
        case WB_CMD_PROMOTE:
        case WB_CMD_PENDING:
        case WB_CMD_S1_CHECK:
        case WB_CMD_APPLY_CORE:
        case WB_CMD_BYE:
            if (out->argc != 0) return false;
            break;
        default:
            break;
    }
    return true;
}

const char *wb_cmd_help_text(void) {
    return
        "workbench " WB_VERSION " commands (one per ssh exec, connection persists)\r\n"
        "  ver                                  version, abi, payload, uptime\r\n"
        "  df [required-bytes]                  read ux0 total/free or check capacity\r\n"
        "  status                               run id, install state, session\r\n"
        "  photo-export <ux0:/VITA-POC/image.jpg|.png> <sha256>  import into Photos\r\n"
        "  install <ux0:/VITA-POC/a.vpk> sha256=HEX [--no-reload]\r\n"
        "  put <ux0:/VITA-POC/a.vpk> <bytes> [sha256=HEX] [--install]\r\n"
        "  r1-status | apply-return <already-authorized-nonce>\r\n"
        "  get <ux0:data/INAP00018/install.log>\r\n"
        "  promote                              apply the staged package (session will drop)\r\n"
        "  reload | rollback | pending | apply-core | s1-check | bye\r\n"
        "install stages a newer verified core; apply-core uses the independent updater.\r\n"
        "Payload reload can keep SSH; a core handoff requires a new connection.\r\n";
}
