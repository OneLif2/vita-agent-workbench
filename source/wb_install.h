#ifndef WB_INSTALL_H
#define WB_INSTALL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wb_zip.h"

/* Platform hooks. The device implementation uses ScePromoterUtil; the host
 * tests drive an in-memory backend through the very same state machine. */
typedef struct wb_inst_backend {
    void *ctx;
    int  (*open_vpk)(void *ctx, const char *path, wb_reader *rd);
    void (*close_vpk)(void *ctx);
    int  (*stage_reset)(void *ctx);
    const wb_writer *(*writer)(void *ctx);
    int  (*save_head)(void *ctx, const uint8_t *head, size_t n);
    int  (*seal_stage)(void *ctx, const char *receipt, const char *running);
    int  (*promote)(void *ctx, const char *stage, bool skip_period);
    /* Installs the payload shipped in the package and swaps it live. */
    int  (*install_payload)(void *ctx, const char *entry, char *version, size_t cap);
    void (*say)(void *ctx, const char *line);
} wb_inst_backend;

typedef struct {
    const char *vpk;
    const char *sha256;      /* optional expected digest, lowercase hex */
    const char *running_ver; /* APP_VER of the running core */
    bool force;
    bool reload;
    bool keep_stage;
    bool allow_other_title;
    bool skip_period;   /* do not unmount app0 around the promote */
    bool promote;       /* false: stage + payload only, core queued */
} wb_inst_request;

typedef struct {
    int code;
    char detail[96];
    char version[16];
    char titleid[12];
    char payload_ver[32];
    uint64_t bytes;
    unsigned files;
    bool promoted;
    bool reloaded;
} wb_inst_result;

int wb_install_run(const wb_inst_request *req, const wb_inst_backend *b, void *ctx, wb_inst_result *res);

#endif
