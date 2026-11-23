/* Only SSH framing, clock, allocation and the input reader are substituted.
 * handlers.inc is verbatim code from the requested release, not a new model. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "wb_err.h"
#include "wb_ssh.h"
#include "wb_sha256.h"
#include "wb_zip.h"
#include "wb_sfo.h"
#include "wb_ver.h"
#ifdef HAS_HASH_SELFTEST
#include "wb_checked_hash.h"
#endif
#include "wb_path.h"
#include <libssh/server.h>
static char logbuf[32768];
static int accepted, denied, exit_sent, dispatches, closed, succeed_ack=1;
static bool allowed=true;
static const char *line;
static const unsigned char *filebytes;
static size_t filesize;
static int alloc_fail, fail_at=-1;
static int chan_write(void *s,const char *p,size_t n) {
    (void)s; size_t at=strlen(logbuf); if (at+n>=sizeof logbuf)return WB_E_LIMIT;
    memcpy(logbuf+at,p,n);logbuf[at+n]=0;return WB_OK;
}
static int upload_read(void *s,void *p,size_t n) {(void)s;(void)p;(void)n;return WB_E_IO;}
static uint64_t now_ms(void) { return 100; }
static void refresh_idle(wb_ssh *s) { s->idle_deadline=100; }
#ifdef WB_TEST_SFTP_EXEC_ONLY
/* Each case owns an EXEC-only channel; no SFTP state should be allocated
 * or cleaned here. The SFTP suites separately cover descriptor teardown. */
static void end_sftp(wb_ssh *s) { if(s->sftp_ro)abort(); }
#endif
int ssh_message_reply_default(ssh_message m){(void)m;denied++;return SSH_OK;}
int ssh_message_channel_request_reply_success(ssh_message m){(void)m;accepted++;return succeed_ack?SSH_OK:SSH_ERROR;}
const char *ssh_message_channel_request_command(ssh_message m){(void)m;return line;}
int ssh_channel_request_send_exit_status(ssh_channel c,int status){(void)c;exit_sent=status;return SSH_OK;}
int ssh_channel_send_eof(ssh_channel c){(void)c;return SSH_OK;}
int ssh_channel_close(ssh_channel c){(void)c;return SSH_OK;}
void ssh_channel_free(ssh_channel c){(void)c;closed++;}
typedef int wb_vfile;
#define INSTALLED_SFO "fixture"
#define WBQ_VERLEN 5
static int queue_sfo_version(const char *p,char *ver){(void)p;memcpy(ver,"01.31",6);return WB_OK;}
static int read_at(const void *c,uint64_t off,void *buf,size_t n){
    (void)c;
    if ((fail_at>=0 && off>=(uint64_t)fail_at)||off>filesize||n>filesize-off)return WB_E_IO;
    memcpy(buf,filebytes+(size_t)off,n);return WB_OK;
}
static int wb_vita_reader_open(const char *p,wb_reader *rd,wb_vfile *fd){
    (void)p;*fd=1;rd->ctx=NULL;rd->size=filesize;rd->read_at=read_at;return WB_OK;
}
static void wb_vita_reader_close(wb_vfile *fd){*fd=0;}
static void *fault_alloc(size_t n){if(alloc_fail){alloc_fail=0;return NULL;}return malloc(n);}
#define malloc fault_alloc
#include "handlers.inc"
#undef malloc
static bool gate(void *p){(void)p;return allowed;}
static bool foreground(void *p,bool ignored){(void)ignored;return gate(p);}
static bool yes(void *p,bool ignored){(void)p;(void)ignored;return true;}
static int dispatch(void *p,const wb_cmd *cmd,wb_out *out,wb_upload *u,int *status){
    (void)p;(void)u;(void)status;dispatches++;
    if(cmd->kind==WB_CMD_PLAN)return do_plan(cmd->argv[0],out);
    if(cmd->kind==WB_CMD_INSPECT)return do_inspect(cmd->argv[0],out);
    return wb_out_puts(out,"ok safe query\n");
}
int main(int argc,char **argv){
    if(argc!=4)return 2;
    wb_ssh s={0}; wb_core core={0};
    s.authenticated=true;s.channel=(ssh_channel)(uintptr_t)1;
    core.gate=gate;core.exec=dispatch;line=argv[2];exit_sent=-1;
    FILE *f=fopen(argv[3],"rb");if(!f)return 2;fseek(f,0,SEEK_END);
    filesize=(size_t)ftell(f);rewind(f);unsigned char *mem=malloc(filesize+1);
    if(!mem||fread(mem,1,filesize,f)!=filesize)return 2;
    fclose(f);filebytes=mem;
    if(!strcmp(argv[1],"oom"))alloc_fail=1;
    if(!strcmp(argv[1],"io"))fail_at=0;
    if(!strcmp(argv[1],"partial"))fail_at=4096;
    if(!strcmp(argv[1],"admission")||!strcmp(argv[1],"ackfail"))allowed=false;
    if(!strcmp(argv[1],"ackfail"))succeed_ack=0;
    if(!strcmp(argv[1],"foreground")){allowed=false;core.gate=NULL;core.foreground=foreground;}
    if(!strcmp(argv[1],"link")){allowed=false;core.gate=NULL;core.foreground=yes;core.link_ok=gate;}
    if(!strcmp(argv[1],"unauth"))s.authenticated=false;
#ifdef HAS_HASH_SELFTEST
    if(!strcmp(argv[1],"selftest")){printf("selftest=%d\n",wb_s2_selftest());free(mem);return 0;}
#endif
    bool ran=run_command(&s,&core,NULL);
    printf("return=%d ack=%d nack=%d dispatch=%d exit=%d closed=%d\n%s",
           ran,accepted,denied,dispatches,exit_sent,closed,logbuf);
    free(mem);return 0;
}
