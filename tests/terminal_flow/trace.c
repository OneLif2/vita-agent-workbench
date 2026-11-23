#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <libssh/server.h>
#include <arpa/inet.h>
#include "wb_ssh.h"
#include "wb_str.h"
#include "wb_ver.h"
#include "wb_err.h"
#include "wb_r1_notice.h"

static wb_ssh g_ssh;
static struct {const char *pin,*ui_line2;uint32_t power_calls;} a={"public-device-fingerprint","owner controls",0};
static wb_r1_notice r1_notice;
static bool local_released,has_focus=true;
static unsigned prompted;
static bool foreground(bool capture){assert(!capture);return has_focus;}
static void review_return_expected(const char *receipt){assert(!strcmp(receipt,"fixture-ready"));prompted++;}
static unsigned ui_seen, online_notes,idle_notes,login_notes;
static char last;
static int connected,ok_to_draw=1,can_bind=1,sig=SSH_PUBLICKEY_STATE_VALID,ack=SSH_OK;
static unsigned char wire_pin[32];
static const char *user="pi";
static uint64_t now_ms(void){return 1234;}
static void refresh_idle(wb_ssh *s){(void)s;}
static void end_sftp(wb_ssh *s){(void)s;}
static void end_shell(wb_ssh *s){(void)s;}
static void fail(wb_ssh *s,const char *msg){(void)s;(void)msg;}
static bool nonblock(int fd){return fd>=0;}
int socket(int a0,int b,int c){(void)a0;(void)b;(void)c;return 1;}
int bind(int fd,const struct sockaddr *p,socklen_t len){(void)fd;(void)p;(void)len;return can_bind?0:-1;}
int listen(int fd,int n){(void)fd;(void)n;return 0;}
int close(int fd){(void)fd;return 0;}
unsigned short htons(unsigned short v){return v;}
in_addr_t inet_addr(const char *p){(void)p;return 0;}
int mbedtls_ct_memcmp(const void *x,const void *y,size_t n){return memcmp(x,y,n);}
int ssh_message_reply_default(ssh_message m){(void)m;return SSH_OK;}
int ssh_message_auth_reply_success(ssh_message m,int partial){(void)m;assert(!partial);return ack;}
int ssh_message_auth_reply_pk_ok_simple(ssh_message m){(void)m;return SSH_OK;}
const char *ssh_message_auth_user(ssh_message m){(void)m;return user;}
int ssh_message_subtype(ssh_message m){(void)m;return SSH_AUTH_METHOD_PUBLICKEY;}
ssh_key ssh_message_auth_pubkey(ssh_message m){(void)m;return (ssh_key)(uintptr_t)1;}
int ssh_message_auth_publickey_state(ssh_message m){(void)m;return sig;}
int ssh_get_publickey_hash(const ssh_key key,int type,unsigned char **p,size_t *n){
    assert(key&&type==SSH_PUBLICKEY_HASH_SHA256);*p=wire_pin;*n=32;return SSH_OK;
}
void ssh_clean_pubkey_hash(unsigned char **p){*p=NULL;}
int ssh_is_connected(ssh_session s){return s&&connected;}
void ssh_disconnect(ssh_session s){(void)s;connected=0;}
void ssh_free(ssh_session s){(void)s;}
void ssh_channel_free(ssh_channel c){(void)c;}
#include "transport.inc"

static void phase_begin(const char *label){assert(!strcmp(label,"PHASE DISPLAY PRESENT"));}
static void phase_end(int rc){(void)rc;}
static int display_terminal(const char *pin,const char *event,bool online){
    assert(pin==a.pin&&event==a.ui_line2);last=online?'T':'I';return ok_to_draw;
}
static bool log_event(const char *s){
    if(!strcmp(s,"UI PRESENT TERMINAL ONLINE"))online_notes++;
    else{assert(!strcmp(s,"UI PRESENT TERMINAL IDLE"));idle_notes++;}
    return true;
}
static void note(void *ctx,const char *s){(void)ctx;assert(!strcmp(s,"AUTH ACCEPTED"));login_notes++;}
static wb_core core={.note=note};
static char frame(void){
    const char *reason=NULL;last='-';
    do{
#include "frame_loop.inc"
    }while(0);
    return reason?(!strcmp(reason,"LISTENER CLOSED")?'X':'E'):last;
}
static void expect(const char *label,char want){
    char got=frame();
    printf("%-36s %c\n",label,got);assert(got==want);
}
static void start(void){
    g_ssh.bind_ready=true;
    assert(wb_ssh_open(&g_ssh,"127.0.0.1",2222,NULL,0)==WB_OK);ui_seen=0;
}
static void peer(void){
    g_ssh.session=(ssh_session)(uintptr_t)1;connected=1;
    g_ssh.mode=(AuthMode){.mode=MODE_B_KEY,.until=50000,.pin={1}};
    user="pi";sig=SSH_PUBLICKEY_STATE_VALID;wire_pin[0]=1;ack=SSH_OK;
}
static bool auth(void){return handle_auth(&g_ssh,NULL,&core);}
int main(void){
    expect("no listener",'X');start();expect("first ready: shared terminal idle",'I');
    peer();expect("TCP accepted only",'I');sig=SSH_PUBLICKEY_STATE_NONE;
    assert(auth());expect("unsigned key probe",'I');wb_ssh_end_session(&g_ssh);
    peer();wire_pin[0]=2;assert(auth());expect("wrong pin denied",'I');wb_ssh_end_session(&g_ssh);
    peer();user="not-owner";assert(auth());expect("wrong user denied",'I');wb_ssh_end_session(&g_ssh);
    peer();sig=SSH_PUBLICKEY_STATE_WRONG;assert(auth());expect("invalid signature",'I');wb_ssh_end_session(&g_ssh);
    peer();ack=SSH_ERROR;assert(!auth());expect("failed success reply",'I');
    assert(!g_ssh.authenticated&&!login_notes);
    wb_ssh_end_session(&g_ssh);peer();assert(auth());assert(login_notes==1);
    ok_to_draw=0;expect("frame error",'E');assert(!online_notes);ok_to_draw=1;
    expect("signed owner login",'T');wb_ssh_end_session(&g_ssh);expect("disconnected",'I');
    for(int i=0;i<20;i++){
        peer();assert(frame()=='I');assert(auth());assert(frame()=='T');
        wb_ssh_end_session(&g_ssh);assert(frame()=='I');
    }
    assert(online_notes==1&&idle_notes==1);
    puts("20 reconnects: same terminal, one online/idle marker each");
    wb_ssh_close_listener(&g_ssh);expect("listener closed",'X');
    can_bind=0;assert(wb_ssh_open(&g_ssh,"127.0.0.1",2222,NULL,0)!=WB_OK);expect("failed new listener",'X');
    can_bind=1;start();expect("new listener lifetime",'I');
    peer();assert(auth());wb_ssh_end_session(&g_ssh);expect("short login before next frame",'I');
    peer();assert(auth());local_released=true;
    r1_notice=(wb_r1_notice){.receipt="fixture-ready",.sent_ms=now_ms(),.power_gen=a.power_calls,.pending=true};
    expect("live channel defers owner prompt",'T');assert(!prompted&&local_released);
    wb_ssh_end_session(&g_ssh);expect("channel close posts owner prompt",'I');assert(prompted==1&&!local_released);
    expect("idle frame never replays prompt",'I');assert(prompted==1);
    r1_notice=(wb_r1_notice){.receipt="fixture-ready",.sent_ms=now_ms(),.power_gen=a.power_calls,.pending=true};
    has_focus=false;expect("background cancels owner prompt",'I');assert(prompted==1&&!r1_notice.pending);has_focus=true;
    puts("PASS: first ready frame uses terminal; failed auth cannot set ONLINE, auth/disconnect never change panels");
    return 0;
}
