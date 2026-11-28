#ifndef WB_GAME_LOGS_PATH_H
#define WB_GAME_LOGS_PATH_H
#include <stdbool.h>
#include <string.h>

#define WB_GAME_DATA_ROOT "ux0:/data/RJGM52237"
#define WB_GAME_LOG_ROOT WB_GAME_DATA_ROOT "/Logs"
#define WB_PERFLAB_DATA_ROOT "ux0:/data/RJGP52237"
#define WB_PERFLAB_LOG_ROOT WB_PERFLAB_DATA_ROOT "/Logs"

/* Namespace selection ONLY, not pathname validation or an access grant.
 * Exact component spelling/type/link checks must still precede a read-only
 * open. In particular, a matching suffix may contain traversal or bad names.
 * This predicate must never be used to authorize a write or an SFTP root.
 * Each title contributes only its Logs directory. Saves and other titles stay out. */
static inline bool wb_one_log_tree(const char *path, const char *root, size_t n) {
    return path && !strncmp(path, root, n) && (path[n] == 0 || path[n] == '/');
}
static inline bool wb_game_logs_path(const char *path) {
    return wb_one_log_tree(path, WB_GAME_LOG_ROOT, sizeof(WB_GAME_LOG_ROOT) - 1) ||
           wb_one_log_tree(path, WB_PERFLAB_LOG_ROOT, sizeof(WB_PERFLAB_LOG_ROOT) - 1);
}
static inline bool wb_game_logs_exact(const char *path) {
    return path && (!strcmp(path, WB_GAME_LOG_ROOT) || !strcmp(path, WB_PERFLAB_LOG_ROOT));
}
static inline bool wb_game_data_parent(const char *path) {
    return path && (!strcmp(path, WB_GAME_DATA_ROOT) || !strcmp(path, WB_PERFLAB_DATA_ROOT));
}
#endif
