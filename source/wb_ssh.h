#ifndef WB_SSH_H
#define WB_SSH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth_modes.h"
#include "wb_cmd.h"
#include "wb_out.h"

struct wb_ssh;
typedef struct wb_upload wb_upload;
struct wb_upload {
    void *ctx;
    int (*read)(void *ctx, void *buf, size_t n);
};

/* Core services the transport calls back into. */
typedef struct wb_core {
    void *ctx;
    bool (*foreground)(void *ctx, bool capture);
    /* Single admission check for EXEC; when set it replaces the
     * foreground/link pair so a locked console can keep serving. */
    bool (*gate)(void *ctx);
    bool (*link_ok)(void *ctx);
    int  (*exec)(void *ctx, const wb_cmd *cmd, wb_out *out, wb_upload *up, int *status);
    void (*note)(void *ctx, const char *event);
    const char *run_hex;
    const char *user_pin_hex;
} wb_core;

typedef struct wb_ssh {
    bool libssh, bind_ready, listening, kex, authenticated, busy, close_after;
    int  listener, accept_used;
    uint64_t accept_window;   /* v1.53 rolling 60 s accept window */
    uint64_t kex_deadline, auth_deadline, idle_deadline, last_command_ms;
    unsigned kex_steps;
    unsigned commands;
    char host_pin[65];
    char peer[4][16];
    int  peer_count;
    char error[64];
    AuthMode mode;
    struct ssh_bind_struct *bind;
    struct ssh_session_struct *session;
    struct ssh_channel_struct *channel;
    struct wb_sftp_frame *sftp_ro; /* owned by the current authenticated channel */
    int shell_cols,shell_rows;
    bool shell_pty; /* negotiated echo only; never allocates an OS PTY */
    struct wb_shell_channel *shell;
} wb_ssh;

bool wb_ssh_host_identity_enrolled(void);
bool wb_ssh_existing_pin(char out[65]);
int  wb_ssh_prepare(wb_ssh *s, const char *user_pin_hex, bool allow_new_identity);
int  wb_ssh_open(wb_ssh *s, const char *ip, uint16_t port, const char (*peers)[16], int peer_count);
int  wb_ssh_service(wb_ssh *s, wb_core *core);
int  wb_ssh_flush_handoff(wb_ssh *s); /* bounded, output-only; no command dispatch */
void wb_ssh_end_session(wb_ssh *s);
void wb_ssh_close_listener(wb_ssh *s);
void wb_ssh_shutdown(wb_ssh *s);
bool wb_ssh_connected(const wb_ssh *s);

#endif
