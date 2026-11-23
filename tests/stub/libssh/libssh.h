#ifndef WB_STUB_LIBSSH_H
#define WB_STUB_LIBSSH_H
#include <stddef.h>
#include <stdint.h>
struct ssh_bind_struct;
struct ssh_session_struct;
struct ssh_channel_struct;
struct ssh_key_struct;
struct ssh_message_struct;
typedef struct ssh_bind_struct *ssh_bind;
typedef struct ssh_session_struct *ssh_session;
typedef struct ssh_channel_struct *ssh_channel;
typedef struct ssh_key_struct *ssh_key;
typedef struct ssh_message_struct *ssh_message;

enum { SSH_OK = 0, SSH_ERROR = -1, SSH_AGAIN = -2 };
enum ssh_publickey_state_e {
    SSH_PUBLICKEY_STATE_ERROR = -1,
    SSH_PUBLICKEY_STATE_NONE = 0,
    SSH_PUBLICKEY_STATE_VALID = 1,
    SSH_PUBLICKEY_STATE_WRONG = 2
};
enum { SSH_AUTH_METHOD_PUBLICKEY = 0x0004 };
enum ssh_keytypes_e { SSH_KEYTYPE_UNKNOWN = 0, SSH_KEYTYPE_ECDSA_P256 = 9 };
enum ssh_publickey_hash_type_e { SSH_PUBLICKEY_HASH_SHA1 = 0, SSH_PUBLICKEY_HASH_MD5 = 1, SSH_PUBLICKEY_HASH_SHA256 = 2 };
enum {
    SSH_BIND_OPTIONS_PROCESS_CONFIG = 0,
    SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS = 1,
    SSH_BIND_OPTIONS_IMPORT_KEY = 2
};
int ssh_init(void);
int ssh_finalize(void);
ssh_bind ssh_bind_new(void);
void ssh_bind_free(ssh_bind b);
int ssh_bind_options_set(ssh_bind b, int type, const void *value);
int ssh_pki_generate_key(int type, int parameter, ssh_key *key);
int ssh_get_publickey_hash(const ssh_key key, int type, unsigned char **hash, size_t *hlen);
void ssh_clean_pubkey_hash(unsigned char **hash);
void ssh_key_free(ssh_key key);
int ssh_key_type(const ssh_key key);
int ssh_key_is_private(const ssh_key key);
typedef int (*ssh_auth_callback)(const char *, char *, size_t, int, int, void *);
enum ssh_file_format_e { SSH_FILE_FORMAT_DEFAULT = 0, SSH_FILE_FORMAT_OPENSSH, SSH_FILE_FORMAT_PEM };
int ssh_pki_import_privkey_base64(const char *, const char *, ssh_auth_callback, void *, ssh_key *);
int ssh_pki_export_privkey_base64_format(const ssh_key, const char *, ssh_auth_callback, void *,
                                         char **, enum ssh_file_format_e);
void ssh_string_free_char(char *);
#endif
