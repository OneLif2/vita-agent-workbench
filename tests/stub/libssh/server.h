#ifndef WB_STUB_LIBSSH_SERVER_H
#define WB_STUB_LIBSSH_SERVER_H
#include <libssh/libssh.h>
enum {
    SSH_REQUEST_AUTH = 1,
    SSH_REQUEST_CHANNEL_OPEN = 2,
    SSH_REQUEST_CHANNEL = 3,
    SSH_REQUEST_SERVICE = 4,
    SSH_REQUEST_GLOBAL = 5
};
enum { SSH_CHANNEL_SESSION = 1, SSH_CHANNEL_DIRECT_TCPIP = 2 };
enum { SSH_CHANNEL_REQUEST_EXEC = 1, SSH_CHANNEL_REQUEST_SHELL = 2, SSH_CHANNEL_REQUEST_SUBSYSTEM = 3,
       SSH_CHANNEL_REQUEST_PTY = 4, SSH_CHANNEL_REQUEST_WINDOW_CHANGE = 5 };
enum { SSH_GLOBAL_REQUEST_TCPIP_FORWARD = 1 };
int ssh_bind_accept_fd(ssh_bind b, ssh_session s, int fd);
int ssh_handle_key_exchange(ssh_session s);
ssh_message ssh_message_get(ssh_session s);
void ssh_message_free(ssh_message m);
int ssh_message_type(ssh_message m);
int ssh_message_subtype(ssh_message m);
int ssh_message_reply_default(ssh_message m);
const char *ssh_message_auth_user(ssh_message m);
ssh_key ssh_message_auth_pubkey(ssh_message m);
int ssh_message_auth_publickey_state(ssh_message m);
int ssh_message_auth_reply_pk_ok_simple(ssh_message m);
int ssh_message_auth_reply_success(ssh_message m, int partial);
ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message m);
ssh_channel ssh_message_channel_request_channel(ssh_message m);
const char *ssh_message_channel_request_command(ssh_message m);
int ssh_message_channel_request_reply_success(ssh_message m);
int ssh_set_blocking(ssh_session s, int blocking);
void ssh_set_auth_methods(ssh_session s, int methods);
int ssh_get_fd(ssh_session s);
int ssh_is_connected(ssh_session s);
void ssh_disconnect(ssh_session s);
void ssh_free(ssh_session s);
ssh_session ssh_new(void);
int ssh_channel_write(ssh_channel c, const void *data, uint32_t len);
int ssh_channel_read_nonblocking(ssh_channel c, void *dest, uint32_t count, int is_stderr);
int ssh_channel_poll_timeout(ssh_channel c, int timeout, int is_stderr);
int ssh_channel_request_send_exit_status(ssh_channel c, int status);
int ssh_channel_send_eof(ssh_channel c);
int ssh_channel_close(ssh_channel c);
void ssh_channel_free(ssh_channel c);
int ssh_channel_is_eof(ssh_channel c);
int ssh_channel_is_closed(ssh_channel c);
#endif
