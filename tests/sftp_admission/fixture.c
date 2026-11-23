#include "wb_ssh.h"
#include "wb_ver.h"
#include <libssh/server.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef CANDIDATE_API
#include "wb_sftp_vita.h"
#include "wb_sftp_frame.h"
#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
/* Fail the test if mere admission touches the filesystem. The real SFTP
 * init/reset and adapter are linked, not replaced by success stubs. */
SceUID sceIoDopen(const char *p){(void)p;abort();}
int sceIoDclose(SceUID fd){(void)fd;abort();}
int sceIoDread(SceUID fd,SceIoDirent *e){(void)fd;(void)e;abort();}
SceUID sceIoOpen(const char *p,int f,SceMode m){(void)p;(void)f;(void)m;abort();}
int sceIoClose(SceUID fd){(void)fd;abort();}
int sceIoRead(SceUID fd,void *p,SceSize n){(void)fd;(void)p;(void)n;abort();}
SceOff sceIoLseek(SceUID fd,SceOff off,int w){(void)fd;(void)off;(void)w;abort();}
#endif
#ifdef WB_TTY_FILE
/* Authenticating/admitting a subsystem must not read/write any disk data. */
#include "wb_tty_file.h"
const char *wb_tty_vopen(bool p,const char *s,uint64_t n,void **h,uint64_t *z){(void)p;(void)s;(void)n;(void)h;(void)z;abort();}
const char *wb_tty_vopen_stream(const char *p,void **h){(void)p;(void)h;abort();}
const char *wb_tty_vmkdir(const char *p){(void)p;abort();}
const char *wb_tty_vprobe(const char *p,const char **v){(void)p;(void)v;abort();}
const char *wb_tty_vwrite(void *h,const uint8_t *b,size_t n){(void)h;(void)b;(void)n;abort();}
const char *wb_tty_vread(void *h,uint8_t *b,size_t n,size_t *got){(void)h;(void)b;(void)n;(void)got;abort();}
const char *wb_tty_vfinish(void *h,bool c,const char *s){(void)h;(void)c;(void)s;abort();}
#endif
struct ssh_channel_struct{int unused;};
struct ssh_message_struct{int subtype;const char *name;ssh_channel channel;};
static int accepted,refused,exit_status,close_count,gates;
#ifdef WB_SCREEN_MIRROR
static int width=80,height=24,dim_reads;
int ssh_message_channel_request_pty_width(ssh_message m){(void)m;dim_reads++;return width;}
int ssh_message_channel_request_pty_height(ssh_message m){(void)m;dim_reads++;return height;}
/* No shell bytes were ACKed in this fixture. Auth, PTY config, denied
 * shells, detached/ended shells, and subsystem init must NEVER publish. */
void wb_mirror_begin(void){abort();}
void wb_mirror_write(const uint8_t *b,size_t n){(void)b;(void)n;abort();}
void wb_mirror_geometry(unsigned w,unsigned h){(void)w;(void)h;abort();}
#endif
static const char *note;
uint64_t sceKernelGetProcessTimeWide(void){return 1000;}
int ssh_message_subtype(ssh_message m){return m->subtype;}
ssh_channel ssh_message_channel_request_channel(ssh_message m){return m->channel;}
const char *ssh_message_channel_request_subsystem(ssh_message m){return m->name;}
int ssh_message_reply_default(ssh_message m){(void)m;refused++;return SSH_OK;}
int ssh_message_channel_request_reply_success(ssh_message m){(void)m;accepted++;return SSH_OK;}
int ssh_channel_request_send_exit_status(ssh_channel c,int value){assert(c);exit_status=value;return SSH_OK;}
int ssh_channel_send_eof(ssh_channel c){assert(c);return SSH_OK;}
int ssh_channel_close(ssh_channel c){assert(c);close_count++;return SSH_OK;}
void ssh_channel_free(ssh_channel c){assert(c);}
/* An exec dispatch is not part of a subsystem request, and is always a test failure. */
static bool run_command(wb_ssh *s,wb_core *c,ssh_message m){(void)s;(void)c;(void)m;abort();}
static bool device_gate(void *ctx){gates++;return *(const int*)ctx!=0;}
static void device_note(void *ctx,const char *msg){(void)ctx;note=msg;}
#ifdef SHELL_API
#include "wb_shell_channel.h"
/* This fixture probes admission and withdrawal only: executing a file/core
 * command or doing channel I/O must fail the test, not fake its success. */
static int never_exec(void *ctx,const wb_cmd *c,wb_out *o,wb_upload *u,int *st){
    (void)ctx;(void)c;(void)o;(void)u;(void)st;abort();
}
static int wb_vita_shell_isdir(void *x,const char*p,wb_out*o){(void)x;(void)p;(void)o;abort();}
static int wb_vita_shell_list(void*x,const char*p,bool l,wb_out*o){(void)l;return wb_vita_shell_isdir(x,p,o);}
#define wb_vita_shell_cat wb_vita_shell_isdir
static int shell_core(void *x,const wb_cmd*c,wb_out*o){(void)x;(void)c;(void)o;abort();}
static int sftp_rd(void*x,uint8_t*p,size_t n){(void)x;(void)p;(void)n;abort();}
static int sftp_wr(void*x,const uint8_t*p,size_t n){(void)x;(void)p;(void)n;abort();}
#endif
#include "actual.inc"

static int probe(const char *label,int type,const char *name,bool auth,int gate,int expected,int wrong_channel) {
    struct ssh_channel_struct channel={0},other={0};
    struct ssh_message_struct m={type,name,wrong_channel?&other:&channel};
    wb_ssh s={0};wb_core core={0};
    s.channel=&channel;s.authenticated=auth;
    core.ctx=&gate;core.gate=gate<0 ? NULL:device_gate;core.note=device_note;
#ifdef SHELL_API
    core.exec=never_exec;
#endif
    accepted=refused=gates=close_count=0;note=NULL;exit_status=-1;
    assert(handle_channel(&s,&core,&m));
    assert(accepted+refused==1);
    if(expected>=0)assert(accepted==expected);
    if(accepted){
        assert(s.channel==&channel && !close_count && exit_status==-1);
#ifdef SHELL_API
        if(type==SSH_CHANNEL_REQUEST_SHELL) {
            assert(s.shell && !s.sftp_ro && !strcmp(note,"WB SHELL OPEN") && gates==1);
            m.subtype=SSH_CHANNEL_REQUEST_EXEC;
            assert(handle_channel(&s,&core,&m) && refused==1);
            m.subtype=SSH_CHANNEL_REQUEST_SUBSYSTEM;m.name="sftp";
            assert(handle_channel(&s,&core,&m) && refused==2);
            gate=0;assert(shell_service(&s,&core)<0); /* fail closed without pumping any input */
            assert(finish_channel(&s,1) && !s.shell && !s.shell_pty);
            printf("%s: ACCEPT, mode locked, withdrawn gate stops next command\n",label);
            return 1;
        }
#endif
#ifdef WB_TTY_FILE
        assert(s.sftp_ro && s.sftp_ro->engine.create==&wb_sftp_vita_write_ops);
        assert(note && !strcmp(note,"SFTP INCOMING OPEN") && gates==1 && auth && gate==1);
#else
        assert(note && strcmp(note,"SFTP READONLY OPEN")==0 && gates==1 && auth && gate==1);
#endif
#ifdef CANDIDATE_API
        assert(s.sftp_ro && s.sftp_ro->engine.ops==&wb_sftp_vita_ops);
        /* A second request cannot renegotiate the active channel. */
        assert(handle_channel(&s,&core,&m) && accepted==1 && refused==1);
        end_sftp(&s);assert(!s.sftp_ro);
#endif
    }else if(!wrong_channel){
        assert(!s.channel && close_count==1 && exit_status==126);
    }else{
        assert(s.channel==&channel && !close_count && exit_status==-1);
    }
    printf("%s: %s\n",label,accepted?"ACCEPT":"DENY");
    return accepted;
}
int main(void){
    int positive=probe("paired + admitted / sftp",SSH_CHANNEL_REQUEST_SUBSYSTEM,"sftp",true,1,-1,0);
    probe("not authenticated / sftp",SSH_CHANNEL_REQUEST_SUBSYSTEM,"sftp",false,1,0,0);
    probe("device gate denied / sftp",SSH_CHANNEL_REQUEST_SUBSYSTEM,"sftp",true,0,0,0);
    probe("missing device gate / sftp",SSH_CHANNEL_REQUEST_SUBSYSTEM,"sftp",true,-1,0,0);
#ifdef SHELL_API
    probe("paired + admitted / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,true,1,1,0);
    probe("unauthenticated / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,false,1,0,0);
    probe("device gate denied / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,true,0,0,0);
    probe("missing gate / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,true,-1,0,0);
    probe("wrong channel / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,true,1,0,1);
    struct ssh_channel_struct c={0};struct ssh_message_struct m={SSH_CHANNEL_REQUEST_PTY,NULL,&c};
    int gate=0;wb_core core={.ctx=&gate,.gate=device_gate,.exec=never_exec};wb_ssh s={.channel=&c};
    accepted=refused=0;gate=1;assert(handle_channel(&s,&core,&m)&&!s.shell_pty && refused==1);
    gate=0;s.authenticated=true;assert(handle_channel(&s,&core,&m)&&!s.shell_pty && refused==2);
    gate=1;assert(handle_channel(&s,&core,&m)&&s.shell_pty && accepted==1);
#ifdef WB_SCREEN_MIRROR
    assert(s.shell_cols==80&&s.shell_rows==24&&dim_reads==2);
    width=132;height=40;
#endif
    assert(handle_channel(&s,&core,&m)&&refused==3);
    m.subtype=SSH_CHANNEL_REQUEST_WINDOW_CHANGE;assert(handle_channel(&s,&core,&m)&&accepted==2);
    m.subtype=SSH_CHANNEL_REQUEST_SHELL;assert(handle_channel(&s,&core,&m)&&accepted==3 && s.shell && s.shell->echo);
    m.subtype=SSH_CHANNEL_REQUEST_WINDOW_CHANGE;assert(handle_channel(&s,&core,&m)&&accepted==4);
#ifdef WB_SCREEN_MIRROR
    assert(s.shell->cols==132&&s.shell->rows==40&&dim_reads==6);
    width=5;height=6;
#endif
    gate=0;assert(handle_channel(&s,&core,&m)&&refused==4);
#ifdef WB_SCREEN_MIRROR
    assert(s.shell->cols==132&&s.shell->rows==40&&dim_reads==6);
#endif
    assert(finish_channel(&s,0) && !s.shell && !s.shell_pty && !s.channel);
    puts("PTY + resize: authenticated and admitted only, single request, editor echo; cleanup verified");
#else
    probe("paired + admitted / shell",SSH_CHANNEL_REQUEST_SHELL,NULL,true,1,0,0);
#endif
    probe("paired + admitted / other subsystem",SSH_CHANNEL_REQUEST_SUBSYSTEM,"other",true,1,0,0);
    probe("paired + admitted / different channel",SSH_CHANNEL_REQUEST_SUBSYSTEM,"sftp",true,1,0,1);
    printf("admitted-sftp=%s; all non-admitted routes denied\n",positive?"accepted":"denied");
    return 0;
}
