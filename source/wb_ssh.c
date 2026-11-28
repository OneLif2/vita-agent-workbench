#include "wb_ssh.h"

#include "wb_err.h"
#include "wb_host_identity.h"
#include "wb_str.h"
#include "wb_ver.h"
#include "wb_sftp_frame.h"
#include "wb_sftp_vita.h"
#include "wb_shell_channel.h"
#ifdef WB_GAME_FEATURE
#include "wb_game_vita.h"
#endif
#include "wb_shell_vfs.h"
#include <stdlib.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <mbedtls/constant_time.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static uint64_t now_ms(void) { return sceKernelGetProcessTimeWide() / 1000u; }

static bool nonblock(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void fail(wb_ssh *s, const char *what) {
    wb_strcpy(s->error, sizeof s->error, what);
}

bool wb_ssh_host_identity_enrolled(void) {
    if (ssh_init() != SSH_OK) return false;
    ssh_key key = NULL;
    const char *why = NULL;
    bool ok = wb_host_identity_get_ex(&key, &why, false) == SSH_OK;
    ssh_key_free(key);
    ssh_finalize();
    return ok;
}

/* Read the actual previously enrolled private-key fingerprint. Never enroll. */
bool wb_ssh_existing_pin(char out[65]) {
    if(!out || ssh_init()!=SSH_OK)return false;
    ssh_key key=NULL;const char *why=NULL;unsigned char d[32];out[0]=0;
    bool ok=wb_host_identity_get_ex(&key,&why,false)==SSH_OK && wb_hi_fingerprint(key,d)==0;
    if(ok){
        static const char x[]="0123456789ABCDEF";
        for(size_t i=0;i<32;i++){out[2*i]=x[d[i]>>4];out[2*i+1]=x[d[i]&15];}
        out[64]=0;
    }
    ssh_key_free(key);ssh_finalize();return ok;
}
int wb_ssh_prepare(wb_ssh *s, const char *user_pin_hex, bool allow_new_identity) {
    if (!s) return WB_E_ARG;
    memset(s, 0, sizeof *s);
    s->listener = -1;
    if (ssh_init() != SSH_OK) { fail(s, "ssh_init"); return WB_E_STATE; }
    s->libssh = true;

    s->bind = ssh_bind_new();
    if (!s->bind) { fail(s, "ssh_bind_new"); return WB_E_STATE; }

    bool no = false;
    ssh_key key = NULL;
    unsigned char *digest = NULL;
    size_t digest_len = 0;
    int rc = WB_E_STATE;
    const char *why = "SSH HOST OPTIONS";

    if (ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no) != SSH_OK ||
        ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, "ecdsa-sha2-nistp256") != SSH_OK)
        goto done;
    if (wb_host_identity_get_ex(&key, &why, allow_new_identity) != SSH_OK) goto done;
    why = "SSH HOST FINGERPRINT";
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &digest, &digest_len) != SSH_OK ||
        !digest || digest_len != 32)
        goto done;
    {
        static const char hexd[] = "0123456789ABCDEF";
        for (size_t i = 0; i < 32; i++) {
            s->host_pin[2 * i] = hexd[digest[i] >> 4];
            s->host_pin[2 * i + 1] = hexd[digest[i] & 15];
        }
        s->host_pin[64] = 0;
    }
    why = "SSH HOST BIND";
    if (ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_IMPORT_KEY, key) != SSH_OK) goto done;
    key = NULL;
    s->bind_ready = true;
    rc = WB_OK;
done:
    ssh_clean_pubkey_hash(&digest);
    ssh_key_free(key);
    /* Do not let successful owner-pin parsing overwrite a failed host identity. */
    if (rc != WB_OK) { fail(s, why); return rc; }

    /* Owner public key digest, loaded by the core from mac-public-pin.txt. */
    if (user_pin_hex && strlen(user_pin_hex) == 64) {
        rc = WB_OK;
        for (unsigned i = 0; i < 32; i++) {
            const char hi = user_pin_hex[2 * i];
            const char lo = user_pin_hex[2 * i + 1];
            const int hv = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
            const int lv = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
            if (hv < 0 || lv < 0) { rc = WB_E_ARG; break; }
            s->mode.pin[i] = (uint8_t)((hv << 4) | lv);
        }
        if (rc == WB_OK && !auth_nonzero(s->mode.pin, sizeof s->mode.pin)) rc = WB_E_ARG;
        s->mode.mode = MODE_B_KEY;
    } else {
        rc = WB_E_ARG;
    }
    if (rc != WB_OK) fail(s, "owner key pin");
    return rc;
}

int wb_ssh_open(wb_ssh *s, const char *ip, uint16_t port, const char (*peers)[16], int peer_count) {
    if (!s || !s->bind_ready || !ip) return WB_E_ARG;
    const struct sockaddr_in src = {
        .sin_len = sizeof src,
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = inet_addr(ip) }
    };
    s->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s->listener < 0) { fail(s, "socket"); return WB_E_IO; }
    if (!nonblock(s->listener) ||
        bind(s->listener, (const struct sockaddr *)&src, sizeof src) != 0 ||
        listen(s->listener, 2) != 0) {
        close(s->listener);
        s->listener = -1;
        fail(s, "bind/listen");
        return WB_E_IO;
    }
    s->listening = true;
    s->peer_count = 0;
    for (int i = 0; i < peer_count && i < 4; i++) {
        if (!peers[i][0]) continue;
        wb_strcpy(s->peer[s->peer_count], sizeof s->peer[0], peers[i]);
        s->peer_count++;
    }
    return WB_OK;
}

static bool peer_ok(const wb_ssh *s, const struct sockaddr_in *peer) {
    if (!peer || peer->sin_family != AF_INET) return false;
    char text[16];
    const char *dots = inet_ntoa(peer->sin_addr);
    if (!dots) return false;
    wb_strcpy(text, sizeof text, dots);
    for (int i = 0; i < s->peer_count; i++)
        if (strcmp(text, s->peer[i]) == 0) return true;
    return false;
}

static void end_sftp(wb_ssh *s) {
    if(s->sftp_ro){wb_sftp_reset(&s->sftp_ro->engine);free(s->sftp_ro);s->sftp_ro=NULL;}
}
static void end_shell(wb_ssh *s) {
#ifdef WB_TTY_FILE
    wb_sh_abort_file(s->shell);
#endif
#ifdef WB_GAME_FEATURE
    if(s->shell)wb_gv_stop(s->shell->game_owner);
#endif
    free(s->shell);s->shell=NULL;s->shell_pty=false;s->shell_cols=s->shell_rows=0;
}
void wb_ssh_end_session(wb_ssh *s) {
    if (!s) return;
    end_sftp(s);
    end_shell(s);
    if (s->channel) { ssh_channel_free(s->channel); s->channel = NULL; }
    if (s->session) { ssh_disconnect(s->session); ssh_free(s->session); s->session = NULL; }
    s->kex = false;
    s->authenticated = false;
    s->busy = false;
}

void wb_ssh_close_listener(wb_ssh *s) {
    if (!s) return;
    if (s->listener >= 0) { close(s->listener); s->listener = -1; }
    s->listening = false;
    wb_ssh_end_session(s);
}

void wb_ssh_shutdown(wb_ssh *s) {
    if (!s) return;
    wb_ssh_close_listener(s);
    if (s->bind) { ssh_bind_free(s->bind); s->bind = NULL; }
    if (s->libssh) { ssh_finalize(); s->libssh = false; }
    auth_end(&s->mode);
}

bool wb_ssh_connected(const wb_ssh *s) { return s && s->session && ssh_is_connected(s->session); }

/* ---- channel I/O ---- */

static int chan_write(void *ctx, const char *buf, size_t n) {
    wb_ssh *s = (wb_ssh *)ctx;
    if (!s || !s->channel) return WB_E_STATE;
    size_t off = 0;
    unsigned spins = 0;
    while (off < n) {
        const int rc = ssh_channel_write(s->channel, buf + off, (uint32_t)(n - off));
        if (rc == SSH_AGAIN) {
            (void)ssh_channel_poll_timeout(s->channel, 0, 0);
            sceKernelDelayThread(2 * 1000);
            if (++spins > 15000) return WB_E_TIMEOUT;
            continue;
        }
        if (rc < 0) return WB_E_IO;
        off += (size_t)rc;
    }
    return WB_OK;
}

static int upload_read(void *ctx, void *buf, size_t n) {
    wb_ssh *s = (wb_ssh *)ctx;
    if (!s || !s->channel) return WB_E_STATE;
    for (unsigned i = 0; i < 15000; i++) {
        const int rc = ssh_channel_read_nonblocking(s->channel, buf, (uint32_t)n, 0);
        if (rc > 0) return rc;
        if (rc == 0) {
            if (ssh_channel_is_eof(s->channel) || !ssh_is_connected(s->session)) return 0;
            (void)ssh_channel_poll_timeout(s->channel, 0, 0);
            sceKernelDelayThread(2 * 1000);
            continue;
        }
        return WB_E_IO;
    }
    return WB_E_TIMEOUT;
}

static void refresh_idle(wb_ssh *s) { s->idle_deadline = now_ms() + WB_IDLE_MS; }

static bool finish_channel(wb_ssh *s, int status) {
    end_sftp(s);
    end_shell(s);
    if (!s->channel) return true;
    (void)ssh_channel_request_send_exit_status(s->channel, status);
    (void)ssh_channel_send_eof(s->channel);
    (void)ssh_channel_close(s->channel);
    ssh_channel_free(s->channel);
    s->channel = NULL;
    refresh_idle(s);
    return true;
}

static int accept_one(wb_ssh *s, wb_core *core) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    memset(&peer, 0, sizeof peer);
    const int fd = accept(s->listener, (struct sockaddr *)&peer, &plen);
    if (fd < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 1 : 0;
    if (plen != sizeof peer || !peer_ok(s, &peer)) {
        close(fd);
        if (core && core->note) core->note(core->ctx, "PEER REJECTED");
        return 1;
    }
    /* v1.53: rolling window instead of a per-process total. A watcher that
     * polls every few seconds used up the old 64-connection budget after a few
     * minutes and every later TCP connect was closed before the SSH banner. */
    const uint64_t accept_now = now_ms();
    if (s->accept_window == 0 || accept_now - s->accept_window >= 60000u) {
        s->accept_window = accept_now;
        s->accept_used = 0;
    }
    if (s->accept_used >= 64) {
        close(fd);
        if (core && core->note) core->note(core->ctx, "PEER LIMIT");
        return 1;   /* keep listening: a spent budget must not end the app */
    }
    s->accept_used++;
    s->session = ssh_new();
    if (!s->session || !nonblock(fd)) { if (fd >= 0) close(fd); return 0; }
#ifdef TCP_NODELAY
    { int one = 1; (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); }
#endif
    { int sz = 524288; (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz); (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz); }
    if (ssh_bind_accept_fd(s->bind, s->session, fd) != SSH_OK) {
        if (ssh_get_fd(s->session) != fd) close(fd);
        return 0;
    }
    ssh_set_blocking(s->session, 0);
    ssh_set_auth_methods(s->session, SSH_AUTH_METHOD_PUBLICKEY);
    s->kex = false;
    s->authenticated = false;
    s->close_after = false;
    s->kex_steps = 0;
    s->kex_deadline = now_ms() + WB_KEX_MS;
    s->auth_deadline = now_ms() + WB_AUTH_MS;
    s->idle_deadline = s->auth_deadline;
    s->mode.mode = MODE_B_KEY;
    s->mode.until = s->auth_deadline;
    s->mode.accepted = false;
    s->mode.attempts = 0;
    s->mode.earliest = 0;
    if (core && core->note) core->note(core->ctx, "PEER ACCEPTED");
    return 1;
}

static bool auth_reply(wb_ssh *s, ssh_message m, bool valid) {
    if (!valid) {
        if (ssh_message_reply_default(m) != SSH_OK) return false;
        return true;
    }
    if (!s->mode.accepted || !auth_nonzero(s->mode.pin, sizeof s->mode.pin)) return false;
    if (ssh_message_auth_reply_success(m, 0) != SSH_OK) return false;
    s->authenticated = true;
    s->accept_used = 0;              /* a real session refunds the window */
    s->accept_window = now_ms();
    refresh_idle(s);
    return true;
}

static bool handle_auth(wb_ssh *s, ssh_message m, wb_core *core) {
    const uint64_t t = now_ms();
    const char *user = ssh_message_auth_user(m);
    const bool user_ok = user && user[0] == 'p' && user[1] == 'i' && user[2] == '\0';

    if (ssh_message_subtype(m) != SSH_AUTH_METHOD_PUBLICKEY) {
        return ssh_message_reply_default(m) == SSH_OK;
    }
    ssh_key key = ssh_message_auth_pubkey(m);
    unsigned char *hash = NULL;
    size_t len = 0;
    const bool known = user_ok && key &&
        ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &len) == SSH_OK && len == 32;
    const enum ssh_publickey_state_e state = ssh_message_auth_publickey_state(m);
    bool ok = false;
    if (state == SSH_PUBLICKEY_STATE_NONE) {
        ok = known && auth_key_probe(&s->mode, hash, t);
        ssh_clean_pubkey_hash(&hash);
        if (ok) return ssh_message_auth_reply_pk_ok_simple(m) == SSH_OK;
        return auth_reply(s, m, false);
    }
    ok = known && auth_key_commit(&s->mode, hash, state == SSH_PUBLICKEY_STATE_VALID, t);
    ssh_clean_pubkey_hash(&hash);
    const bool replied = auth_reply(s, m, ok);
    if (ok && replied && core && core->note) core->note(core->ctx, "AUTH ACCEPTED");
    return replied;
}

/* ACK means the request was received, not that it was permitted. Never
 * dispatch this branch. Auth, shell, subsystem and forwarded channels still
 * use protocol-level refusal. Only fixed local reasons are emitted. */
static bool deny_exec(wb_ssh *s, ssh_message m, wb_out *out, const char *reason) {
    if (ssh_message_channel_request_reply_success(m) != SSH_OK) return false;
    const int wrc = wb_out_printf(out, "ERR denied %s\n", reason);
    const bool closed = finish_channel(s, 125);
    return wrc == WB_OK && closed;
}

static bool run_command(wb_ssh *s, wb_core *core, ssh_message m) {
    wb_out out;
    out.ctx = s;
    out.write = chan_write;

    const char *cmdline = ssh_message_channel_request_command(m);
    const size_t len = cmdline ? strlen(cmdline) : 0;

    if (!s->authenticated || !core || !core->exec) {
        (void)ssh_message_reply_default(m);
        return finish_channel(s, 126);
    }
    if (core->gate) {
        if (!core->gate(core->ctx)) {
            return deny_exec(s, m, &out, "admission");
        }
    } else {
        if (core->foreground && !core->foreground(core->ctx, false)) {
            return deny_exec(s, m, &out, "foreground");
        }
        if (core->link_ok && !core->link_ok(core->ctx)) {
            return deny_exec(s, m, &out, "link");
        }
    }

    wb_cmd cmd;
    if (!wb_cmd_parse(cmdline, len, &cmd)) {
        return deny_exec(s, m, &out, "command");
    }

    if (ssh_message_channel_request_reply_success(m) != SSH_OK) return false;

    wb_upload up;
    up.ctx = s;
    up.read = upload_read;
    int status = 0;
    s->busy = true;
    const int rc = core->exec(core->ctx, &cmd, &out, &up, &status);
    s->busy = false;
    s->commands++;
    s->last_command_ms = now_ms();

    if (rc != WB_OK) {
        (void)wb_out_printf(&out, "ERR %s\n", rc == WB_E_NOMEM ? "nomem" : wb_err_name(rc));
        if (!status) status = 1;
    }
    if (cmd.kind == WB_CMD_BYE) s->close_after = true;
    return finish_channel(s, status);
}
static bool sftp_admitted(wb_ssh *s,wb_core *core) {
    return s->authenticated && core && core->gate && core->gate(core->ctx);
}
static int sftp_rd(void *p,uint8_t *buf,size_t cap) {
    wb_ssh *s=p;
    int n=ssh_channel_read_nonblocking(s->channel,buf,(uint32_t)cap,0);
    if(n==0 && !ssh_channel_is_eof(s->channel)){
        (void)ssh_channel_poll_timeout(s->channel,0,0);
        n=ssh_channel_read_nonblocking(s->channel,buf,(uint32_t)cap,0);
    }
    if(n>0){refresh_idle(s);return n;}
    if(n<0 && n!=SSH_AGAIN && n!=SSH_EOF)return -1;
    return n==SSH_EOF || ssh_channel_is_eof(s->channel)?-2:0;
}
static int sftp_wr(void *p,const uint8_t *buf,size_t n) {
    wb_ssh *s=p;
    int k=ssh_channel_write(s->channel,buf,(uint32_t)n);
    if(k>0)refresh_idle(s);
    return k==SSH_AGAIN?0:k;
}
/* The interactive shell buffers the current command's receipt. Give it a
 * bounded chance to leave; an unresponsive/disconnected peer must not keep
 * the outgoing process resident. Never read or service another command. */
int wb_ssh_flush_handoff(wb_ssh *s) {
    if(!s || !s->shell || !s->shell->queued)return WB_OK;
    if(!s->channel)return WB_E_IO;
    for(unsigned i=0;i<12;i++) {
        if(wb_sh_flush(s->shell,s,sftp_wr)<0)return WB_E_IO;
        if(!s->shell->queued)return WB_OK;
        sceKernelDelayThread(2000);
    }
    return WB_E_TIMEOUT;
}
/* Only the engine can supply a parsed, allowlisted WB command. Never map
 * text to an OS interpreter, spawn a process or consume binary upload stdin. */
static int shell_core(void *ctx,const wb_cmd *cmd,wb_out *out) {
    wb_core *core=ctx;int status=0;
    if(!core || !core->exec || !core->gate || !core->gate(core->ctx))return -1;
    if(cmd->kind==WB_CMD_PUT || cmd->kind==WB_CMD_GET || cmd->kind==WB_CMD_BYE)
        return wb_out_puts(out,"ERR use dedicated file transfer or exit\n")<0?-1:1;
    int rc=core->exec(core->ctx,cmd,out,NULL,&status);
    if(rc!=WB_OK && wb_out_printf(out,"ERR %s\n",wb_err_name(rc))<0)return -1;
    return rc!=WB_OK || status ? 1 : 0;
}
static int shell_service(wb_ssh *s,wb_core *core) {
    if(!sftp_admitted(s,core))return -1;
    wb_shell_ops ops={.ctx=core,.isdir=wb_vita_shell_isdir,.list=wb_vita_shell_list,
                      .cat=wb_vita_shell_cat,.core_exec=shell_core};
    unsigned count=0;
    s->busy=true;
    int k=wb_sh_pump(s->shell,s,sftp_rd,sftp_wr,&ops,&count);
    s->busy=false;
    if(count){s->commands+=count;s->last_command_ms=now_ms();}
    return k;
}
static bool handle_channel(wb_ssh *s, wb_core *core, ssh_message m) {
    if (!s->channel || ssh_message_channel_request_channel(m) != s->channel) {
        return ssh_message_reply_default(m) == SSH_OK;
    }
    const int sub = ssh_message_subtype(m);
    if(s->sftp_ro)return ssh_message_reply_default(m)==SSH_OK;
    if(sub==SSH_CHANNEL_REQUEST_WINDOW_CHANGE && s->shell_pty && sftp_admitted(s,core)){
        if(ssh_message_channel_request_reply_success(m)!=SSH_OK)return false;
#ifdef WB_SCREEN_MIRROR
        s->shell_cols=ssh_message_channel_request_pty_width(m);
        s->shell_rows=ssh_message_channel_request_pty_height(m);
        if(s->shell)wb_sh_set_geometry(s->shell,s->shell_cols,s->shell_rows);
#endif
        return true;
    }
    if(s->shell)return ssh_message_reply_default(m)==SSH_OK;
    if(sub==SSH_CHANNEL_REQUEST_PTY) {
        if(s->shell_pty || !sftp_admitted(s,core))return ssh_message_reply_default(m)==SSH_OK;
        if(ssh_message_channel_request_reply_success(m)!=SSH_OK)return false;
        s->shell_pty=true;
#ifdef WB_SCREEN_MIRROR
        s->shell_cols=ssh_message_channel_request_pty_width(m);
        s->shell_rows=ssh_message_channel_request_pty_height(m);
#endif
        refresh_idle(s);return true;
    }
    if(sub==SSH_CHANNEL_REQUEST_SHELL && sftp_admitted(s,core) && core->exec) {
        wb_shell_channel *ch=calloc(1,sizeof *ch);
        if(!ch || wb_sh_start(ch,s->shell_pty)<0) {
            free(ch);(void)ssh_message_reply_default(m);return finish_channel(s,1);
        }
        if(ssh_message_channel_request_reply_success(m)!=SSH_OK){free(ch);return false;}
        wb_sh_set_geometry(ch,s->shell_cols,s->shell_rows);
        s->shell=ch;refresh_idle(s);if(core->note)core->note(core->ctx,"WB SHELL OPEN");
        return true;
    }
    if(sub==SSH_CHANNEL_REQUEST_SUBSYSTEM) {
        const char *name=ssh_message_channel_request_subsystem(m);
        if(name && !strcmp(name,"sftp") && !s->shell_pty && sftp_admitted(s,core)) {
            wb_sftp_frame *f=calloc(1,sizeof *f);
            if(!f)return ssh_message_reply_default(m)==SSH_OK;
            wb_sftp_init(&f->engine,&wb_sftp_vita_ops);s->sftp_ro=f;
#ifdef WB_TTY_FILE
            wb_sftp_enable_write(&f->engine,&wb_sftp_vita_write_ops);
#endif
            if(ssh_message_channel_request_reply_success(m)!=SSH_OK){end_sftp(s);return false;}
            refresh_idle(s);
#ifdef WB_TTY_FILE
            if(core->note)core->note(core->ctx,"SFTP INCOMING OPEN");
#else
            if(core->note)core->note(core->ctx,"SFTP READONLY OPEN");
#endif
            return true;
        }
    }
    if (sub == SSH_CHANNEL_REQUEST_EXEC) return run_command(s, core, m);
    if (sub == SSH_CHANNEL_REQUEST_SHELL || sub == SSH_CHANNEL_REQUEST_SUBSYSTEM) {
        (void)ssh_message_reply_default(m);
        if (core && core->note) core->note(core->ctx, "DENY SHELL");
        return finish_channel(s, 126);
    }
    (void)ssh_message_reply_default(m);
    return true;
}

static bool request(wb_ssh *s, wb_core *core, ssh_message m) {
    const int type = ssh_message_type(m);
    const int sub = ssh_message_subtype(m);

    if (type == SSH_REQUEST_AUTH && !s->authenticated) return handle_auth(s, m, core);

    if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_SESSION) {
        if (!s->authenticated) return ssh_message_reply_default(m) == SSH_OK;
        if (s->channel) { (void)ssh_message_reply_default(m); return true; }
        s->channel = ssh_message_channel_request_open_reply_accept(m);
        refresh_idle(s);
        return s->channel != NULL;
    }
    if (type == SSH_REQUEST_CHANNEL && s->channel) return handle_channel(s, core, m);

    if (type == SSH_REQUEST_GLOBAL) {
        if (sub == SSH_GLOBAL_REQUEST_TCPIP_FORWARD) {
            if (core && core->note) core->note(core->ctx, "DENY FORWARD");
            return ssh_message_reply_default(m) == SSH_OK;
        }
        /* OpenSSH ServerAliveInterval sends global keepalive@openssh.com requests.
         * Reply default (SSH_MSG_REQUEST_FAILURE) without closing the active channel. */
        if (s->authenticated && s->channel) refresh_idle(s);
        return ssh_message_reply_default(m) == SSH_OK;
    }
    if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_DIRECT_TCPIP) {
        if (core && core->note) core->note(core->ctx, "DENY FORWARD");
        return ssh_message_reply_default(m) == SSH_OK;
    }
    if (type == SSH_REQUEST_CHANNEL || type == SSH_REQUEST_CHANNEL_OPEN) {
        (void)ssh_message_reply_default(m);
        return finish_channel(s, 126);
    }
    return ssh_message_reply_default(m) == SSH_OK;
}

/* Already admitted owner PTY only. No timeout relaxation for unauthenticated,
 * exec, subsystem, password/challenge, closing or dead channels. EOF/network
 * errors and local revocation still follow the ordinary shutdown path. */
static bool interactive_idle_keep(const wb_ssh *s) {
    return s && s->authenticated && s->mode.mode==MODE_B_KEY && s->mode.accepted &&
           auth_nonzero(s->mode.pin,sizeof s->mode.pin) && s->shell_pty && s->shell &&
           !s->shell->closing && s->channel && wb_ssh_connected(s) &&
           !ssh_channel_is_closed(s->channel) && !ssh_channel_is_eof(s->channel);
}

int wb_ssh_service(wb_ssh *s, wb_core *core) {
    if (!s || !s->listening) return 1;
    if (!s->session) return accept_one(s, core);

    const uint64_t t = now_ms();
    if (!s->kex && t >= s->kex_deadline) { fail(s, "kex timeout"); wb_ssh_end_session(s); return 1; }
    if (!s->authenticated && t >= s->auth_deadline) { fail(s, "auth timeout"); wb_ssh_end_session(s); return 1; }
    if (s->authenticated && t >= s->idle_deadline && !interactive_idle_keep(s)) { fail(s, "idle timeout"); wb_ssh_end_session(s); return 1; }

    if (!s->kex) {
        s->kex_steps++;
        const int rc = ssh_handle_key_exchange(s->session);
        if (rc == SSH_AGAIN) return 1;
        if (rc != SSH_OK) { fail(s, "key exchange"); wb_ssh_end_session(s); return 1; }
        s->kex = true;
        if (core && core->note) core->note(core->ctx, "KEY EXCHANGE COMPLETE");
        return 1;
    }

    ssh_message m = ssh_message_get(s->session);
    if (!m) {
        if (s->channel && ssh_channel_is_closed(s->channel)) {
            end_sftp(s);end_shell(s);ssh_channel_free(s->channel);s->channel=NULL;
        } else if(s->sftp_ro) {
            int k=sftp_admitted(s,core)?wb_sf_pump(s->sftp_ro,s,sftp_rd,sftp_wr):-1;
            if(k<=0)(void)finish_channel(s,k==0?0:1);
        } else if(s->shell) {
            int k=shell_service(s,core);
            if(k<=0)(void)finish_channel(s,k==0?0:1);
        }
        if (!ssh_is_connected(s->session)) {
            if (core && core->note) core->note(core->ctx, "PEER CLOSED");
            wb_ssh_end_session(s);
        }
        return 1;
    }
    const bool ok = request(s, core, m);
    ssh_message_free(m);
    if (!ok) { fail(s, "protocol error"); wb_ssh_end_session(s); return 1; }
    if (s->close_after) { s->close_after = false; wb_ssh_end_session(s); }
    return 1;
}

void wb_ssh_keepalive(wb_ssh *s) {
    if (!s || !s->session || !s->authenticated || !ssh_is_connected(s->session)) return;
    for (unsigned i = 0; i < 4; i++) {
        ssh_message m = ssh_message_get(s->session);
        if (!m) break;
        if (ssh_message_type(m) == SSH_REQUEST_GLOBAL) refresh_idle(s);
        (void)ssh_message_reply_default(m);
        ssh_message_free(m);
    }
}
