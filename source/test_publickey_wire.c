#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include "auth_modes.h"

static void server(int fd,ssh_key key,const unsigned char *owner,int good){
    ssh_bind b=ssh_bind_new();ssh_session s=ssh_new();bool no=false;
    assert(b&&s&&ssh_bind_options_set(b,SSH_BIND_OPTIONS_PROCESS_CONFIG,&no)==SSH_OK);
    assert(ssh_bind_options_set(b,SSH_BIND_OPTIONS_IMPORT_KEY,key)==SSH_OK);
    assert(ssh_bind_accept_fd(b,s,fd)==SSH_OK&&ssh_handle_key_exchange(s)==SSH_OK);
    ssh_set_auth_methods(s,SSH_AUTH_METHOD_PUBLICKEY);
    AuthMode a={.mode=MODE_B_KEY,.until=10000};memcpy(a.pin,owner,sizeof a.pin);
    ssh_message m;unsigned probe=0,sign=0;
    while((m=ssh_message_get(s))!=NULL){
        bool handled=false;
        const char *u=ssh_message_auth_user(m);
        if(ssh_message_type(m)==SSH_REQUEST_AUTH&&ssh_message_subtype(m)==SSH_AUTH_METHOD_PUBLICKEY&&u&&!strcmp(u,"pi")){
            ssh_key remote=ssh_message_auth_pubkey(m);
            unsigned char *digest=NULL;size_t len=0;
            assert(remote&&ssh_get_publickey_hash(remote,SSH_PUBLICKEY_HASH_SHA256,&digest,&len)==SSH_OK&&len==32);
            enum ssh_publickey_state_e state=ssh_message_auth_publickey_state(m);
            if(state==SSH_PUBLICKEY_STATE_NONE) {
                probe++;assert(!a.accepted);
                if(auth_key_probe(&a,digest,1)){assert(ssh_message_auth_reply_pk_ok_simple(m)==SSH_OK);handled=true;}
            } else {
                sign++;
                if(auth_key_commit(&a,digest,state==SSH_PUBLICKEY_STATE_VALID,1)){
                    assert(ssh_message_auth_reply_success(m,0)==SSH_OK);handled=true;
                }
            }
            ssh_clean_pubkey_hash(&digest);
        }
        if(!handled)assert(ssh_message_reply_default(m)==SSH_OK);
        ssh_message_free(m);
    }
    assert(probe==1&&sign==1&&a.accepted==(good!=0));
    auth_end(&a);ssh_disconnect(s);ssh_free(s);ssh_bind_free(b);
}
static void run(int good) {
    ssh_key key=NULL,user=NULL,wrong=NULL;
    assert(ssh_pki_generate_key(SSH_KEYTYPE_ECDSA_P256,NULL,&key)==SSH_OK);
    assert(ssh_pki_generate_key(SSH_KEYTYPE_ECDSA_P256,NULL,&user)==SSH_OK);
    assert(ssh_pki_generate_key(SSH_KEYTYPE_ECDSA_P256,NULL,&wrong)==SSH_OK);
    unsigned char *pin=NULL,*owner=NULL;size_t n=0,on=0;
    assert(ssh_get_publickey_hash(key,SSH_PUBLICKEY_HASH_SHA256,&pin,&n)==SSH_OK&&n==32);
    assert(ssh_get_publickey_hash(user,SSH_PUBLICKEY_HASH_SHA256,&owner,&on)==SSH_OK&&on==32);
    int fd[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    pid_t pid=fork();assert(pid>=0);
    if(!pid){close(fd[0]);ssh_key_free(user);ssh_key_free(wrong);server(fd[1],key,owner,good);_Exit(0);}
    close(fd[1]);ssh_key_free(key);
    ssh_session s=ssh_new(); bool no=false;assert(s);
    assert(ssh_options_set(s,SSH_OPTIONS_PROCESS_CONFIG,&no)==SSH_OK);
    assert(ssh_options_set(s,SSH_OPTIONS_HOST,"local-synthetic")==SSH_OK);
    assert(ssh_options_set(s,SSH_OPTIONS_USER,"pi")==SSH_OK);
    assert(ssh_options_set(s,SSH_OPTIONS_FD,&fd[0])==SSH_OK&&ssh_connect(s)==SSH_OK);
    ssh_key peer=NULL;unsigned char *got=NULL;size_t gn=0;
    assert(ssh_get_server_publickey(s,&peer)==SSH_OK);
    assert(ssh_get_publickey_hash(peer,SSH_PUBLICKEY_HASH_SHA256,&got,&gn)==SSH_OK);
    assert(n==gn&&mbedtls_ct_memcmp(pin,got,n)==0);
    assert(ssh_userauth_try_publickey(s,NULL,user)==SSH_AUTH_SUCCESS);
    assert(ssh_userauth_publickey(s,NULL,good?user:wrong)==(good?SSH_AUTH_SUCCESS:SSH_AUTH_DENIED));
    ssh_clean_pubkey_hash(&got);ssh_clean_pubkey_hash(&pin);ssh_clean_pubkey_hash(&owner);
    ssh_key_free(peer);ssh_key_free(user);ssh_key_free(wrong);
    ssh_disconnect(s);ssh_free(s);close(fd[0]);
    int st;assert(waitpid(pid,&st,0)==pid&&WIFEXITED(st)&&WEXITSTATUS(st)==0);
}
int main(void){alarm(12);assert(ssh_init()==SSH_OK);run(0);run(1);ssh_finalize();puts("PASS: B, pinned host then public probe only, reject wrong signed key, accept enrolled valid signature");}
