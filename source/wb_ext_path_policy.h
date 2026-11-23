#ifndef WB_EXT_PATH_POLICY_H
#define WB_EXT_PATH_POLICY_H
#include "wb_cmd.h"
#include "wb_path.h"
#include "wb_ver.h"
#include <string.h>

/* The immutable p2.1 payload's own checks predate the private identity.
 * Validate the exact spelling and every component BEFORE any module load,
 * for both "ext <verb>" and the shorthand. Never pass an alternate mount
 * through to the payload. wb_path_under rejects dot segments, extra colons,
 * empty path components, backslashes and overlong names. */
static inline bool wb_ext_path_ok(const char *path, bool write) {
    if (!path) return false;
    /* WBQ2's approval copy and final hand-off directory are owned by INAP00019.
     * Restrict writes by positive roots, not a blacklist of path spellings
     * (case and filesystem aliases). Also deny renaming an allowed root itself. */
    if (write && !wb_path_under(path, WB_ROOT) && !wb_path_under(path, WB_INCOMING))
        return false;
    size_t n = strlen(path);
    if (!n || n >= WB_CMD_ARG_MAX) return false;
    char canonical[WB_CMD_ARG_MAX];
    if (!write && path[n-1] == '/') {
        if (n < 2 || path[n-2] == '/') return false;
        memcpy(canonical, path, n-1);
        canonical[n-1] = 0;
        path = canonical;
    }
    static const char *const roots[] = {"ux0:data", "ux0:/VITA-POC", "ux0:/app"};
    for (size_t i = 0; i < (write ? 2u : 3u); ++i) {
        const size_t k = strlen(roots[i]);
        if (strncmp(path, roots[i], k)) continue; /* payload matches case */
        if (path[k] == 0) return !write;         /* read-only directory root */
        if (path[k] == '/' && wb_path_under(path, roots[i])) return true;
    }
    return false;
}
static inline bool wb_ext_operands_ok(const char *cmd, int argc, char *const argv[]) {
    const bool read = !strcmp(cmd,"ls") || !strcmp(cmd,"stat");
    const bool mv = !strcmp(cmd,"mv");
    const bool write = mv || !strcmp(cmd,"rm") || !strcmp(cmd,"mkdir");
    if (!read && !write) return true;  /* no filesystem operands in p2.1 */
    if (argc != (mv ? 2 : 1)) return false;
    for (int i = 0; i < argc; ++i)
        if (!wb_ext_path_ok(argv[i], write)) return false;
    return true;
}
#endif
