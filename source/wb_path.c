#include "wb_path.h"

#include "wb_str.h"
#include "wb_ver.h"

#include <stdio.h>
#include <string.h>

static int lower_of(int c) { return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c; }

bool wb_path_under(const char *path, const char *prefix) {
    if (!path || !prefix) return false;
    const size_t n = strlen(prefix);
    if (strlen(path) <= n) return false;
    for (size_t i = 0; i < n; i++)
        if (lower_of((unsigned char)path[i]) != lower_of((unsigned char)prefix[i])) return false;
    if (path[n] != '/') return false;

    for (const char *part = path + n + 1;;) {
        const char *end = strchr(part, '/');
        const size_t len = end ? (size_t)(end - part) : strlen(part);
        if (!len || len > 100 || part[len - 1] == '.' || part[len - 1] == ' ')
            return false;
        for (size_t i = 0; i < len; i++) {
            const unsigned char c = (unsigned char)part[i];
            if (c < 0x20 || c == 0x7f || c == '\\' || c == ':') return false;
        }
        if (!end) return true;
        part = end + 1;
    }
}

int wb_path_join(char *out, size_t cap, const char *root, const char *rel) {
    if (!out || cap == 0 || !root) return -1;
    size_t n = (size_t)snprintf(out, cap, "%s/%s", root, rel ? rel : "");
    if (n >= cap) { out[0] = 0; return -1; }
    return (int)n;
}

bool wb_path_ipv4(const char *s) {
    if (!s) return false;
    unsigned a, b, c, d;
    char tail;
    if (4 != sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail)) return false;
    return a <= 255 && b <= 255 && c <= 255 && d <= 255;
}

bool wb_path_name_ok(const char *name) {
    if (!name || !*name) return false;
    const size_t n = strlen(name);
    if (n > 100 || name[n - 1] == '.' || name[n - 1] == ' ') return false;
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f) return false;
        if (c == '/' || c == '\\' || c == ':') return false;
    }
    return true;
}

bool wb_install_source_ok(const char *path) {
    if (!path) return false;
    if (wb_path_under(path, WB_INCOMING)) return true;
    if (wb_path_under(path, WB_ROOT)) return true;
    return false;
}
