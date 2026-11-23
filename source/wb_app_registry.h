#ifndef WB_APP_REGISTRY_H
#define WB_APP_REGISTRY_H

/* Build-time policy: outside the runtime data/upload roots. No network or device-file fallback. */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "wb_app_local.h"

typedef struct {
    const char *title, *version, *sha256, *cases;
} wb_reg_entry;
static const wb_reg_entry wb_reg_entries[] = {
#include <wb_registry_data.inc>
};
#define WB_REG_ROWS (sizeof(wb_reg_entries) / sizeof(wb_reg_entries[0]))
typedef enum { WB_REG_OK=0, WB_REG_TITLE, WB_REG_VERSION, WB_REG_SHA256, WB_REG_CASE } wb_reg_result;

static inline bool wb_reg_has_title(const char *title) {
    if (!title) return false;
    for (size_t i=0; i<WB_REG_ROWS; ++i)
        if (!strcmp(title,wb_reg_entries[i].title)) return true;
    return wb_app_local_title(title);
}
static inline const wb_reg_entry *wb_reg_entry_for(const char *title, const char *ver) {
    if (!title || !ver) return NULL;
    for (size_t i=0; i<WB_REG_ROWS; ++i)
        if (!strcmp(title,wb_reg_entries[i].title) && !strcmp(ver,wb_reg_entries[i].version))
            return &wb_reg_entries[i];
    return NULL;
}
static inline wb_reg_result wb_reg_install(const char *title,const char *ver,const char *shahex) {
    if (!wb_reg_has_title(title)) return WB_REG_TITLE;
    const wb_reg_entry *row=wb_reg_entry_for(title,ver);
    if (row) return shahex && !strcmp(shahex,row->sha256) ? WB_REG_OK : WB_REG_SHA256;
    /* Runtime owner-signed rows carry no test case, so they can never be
     * reached by wb_reg_launch(): this is an installation channel only. */
    const int local = wb_app_local_match(title,ver,shahex);
    if (local == 1) return WB_REG_OK;
    return local == 0 ? WB_REG_SHA256 : WB_REG_VERSION;
}
static inline wb_reg_result wb_reg_launch(const char *title,const char *ver,const char *case_name) {
    if (!wb_reg_has_title(title)) return WB_REG_TITLE;
    const wb_reg_entry *row=wb_reg_entry_for(title,ver);
    /* A runtime owner-signed row carries no case at all, so it can only ever
     * answer "no approved case" -- never WB_REG_OK. */
    if (!row) return wb_app_local_match(title,ver,NULL) >= 0 ? WB_REG_CASE : WB_REG_VERSION;
    if (!case_name || !*case_name) return WB_REG_CASE;
    const size_t n=strlen(case_name);
    for (const char *p=row->cases; *p;) {
        const char *end=strchr(p,',');
        const size_t k=end ? (size_t)(end-p) : strlen(p);
        if (k==n && !memcmp(case_name,p,k)) return WB_REG_OK;
        if (!end) break;
        p=end+1;
    }
    return WB_REG_CASE;
}
static inline const char *wb_reg_reason(wb_reg_result r) {
    switch (r) {
        case WB_REG_OK: return "approved";
        case WB_REG_TITLE: return "registry-title";
        case WB_REG_VERSION: return "registry-version";
        case WB_REG_SHA256: return "registry-sha256";
        case WB_REG_CASE: return "registry-case";
        default: return "registry-invalid";
    }
}
#endif
