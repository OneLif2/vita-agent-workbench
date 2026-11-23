#ifndef WB_PATH_H
#define WB_PATH_H

#include <stdbool.h>
#include <stddef.h>

/* True for a lexical descendant with valid path components. */
bool wb_path_under(const char *path, const char *prefix);
int wb_path_join(char *out, size_t cap, const char *root, const char *rel);
bool wb_path_ipv4(const char *s);
/* Single file name: no separators, no device colon, 1..100 printable chars. */
bool wb_path_name_ok(const char *name);
/* Install source policy: only the owner upload directory and WB_ROOT. */
bool wb_install_source_ok(const char *path);

#endif
