/* Exercise actual wire descriptor and snapshot with stubs that never write. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_cmd.h"
#include "wb_shell.h"
#include "wb_out.h"
#include "wb_return_policy.h"
#include "focus_guard.h"
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL in status fixture line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
#define WB_STANDING_PATH "savedata0:/fixture-standing-consent"
#define DIGEST "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
enum { SCE_NETCTL_STATE_DISCONNECTED,SCE_NETCTL_STATE_CONNECTING,SCE_NETCTL_STATE_FINALIZING,SCE_NETCTL_STATE_CONNECTED,
       SCE_NETCTL_INFO_GET_DEVICE };
typedef union {unsigned int device;char anon[256];} SceNetCtlInfo;
typedef struct {
    int cb,app_rc,rtc_rc;
    struct {int isSystemUiOverlaid;} state;
    bool power_latched,counters_same;
    uint64_t tick,previous_tick;
} FocusEvidence;
typedef struct {char stub;} wb_standing_disk;
typedef struct {bool listening,authenticated,accepted,paired,session,channel,shell,pty,sftp,transport;} fixture_ssh;
static fixture_ssh g_ssh;
static struct {bool ctl;char run_hex[17];} a={true,"ABABABABABABABAB"};
static int probes,net_state,net_next,net_rc,device,dev_rc,net_calls,pub,seal,stored,reads,active,revoked;
static FocusEvidence e;
static char output[1024],pending[WBQ_CAP+2],private_seal[WBQ_CAP+2];
static size_t bytes;
static char next_version[6];
static uint64_t now_ms(void){return UINT64_C(1234567890123);}
static bool wb_standing_owner_pty(void) {
    return g_ssh.authenticated&&g_ssh.accepted&&g_ssh.paired&&g_ssh.session&&g_ssh.channel&&
           g_ssh.shell&&g_ssh.pty&&!g_ssh.sftp;
}
static bool wb_ssh_connected(const fixture_ssh *s){CK(s==&g_ssh);return s->transport;}
static bool wb_standing_active(wb_standing_disk *r){CK(r);return active;}
static bool wb_standing_revoked(void){return revoked;}
static FocusEvidence fixture_read_focus(void){++probes;return e;}
static FocusResult fixture_classify(const FocusEvidence *in,bool capture){
    CK(!capture);
    return focus_result(in->cb,in->power_latched?1:0,in->app_rc,in->state.isSystemUiOverlaid,
                        in->rtc_rc,in->tick,capture,in->counters_same,in->previous_tick);
}
static int sceNetCtlInetGetState(int *out){CK(out);*out=net_calls++?net_next:net_state;return net_rc;}
static int sceNetCtlInetGetInfo(int kind,SceNetCtlInfo *out){CK(kind==SCE_NETCTL_INFO_GET_DEVICE&&out);out->device=(unsigned)device;return dev_rc;}
static int r1_exists(const char *p){
    if(!strcmp(p,WB_PENDING_PATH))return pub;
    if(!strcmp(p,WBQ_SEAL))return seal;
    CK(!strcmp(p,WB_STANDING_PATH));return stored;
}
static int wb_vita_read_small(const char *p,void *out,size_t cap,size_t *n){
    ++reads;const char *s=NULL;
    if(!strcmp(p,WB_PENDING_PATH))s=pending;
    else if(!strcmp(p,WBQ_SEAL))s=private_seal;
    CK(s&&n&&out);*n=strlen(s);if(*n>cap)*n=cap;
    memcpy(out,s,*n);return WB_OK;
}
/* Only the SDK sampler/classifier are present, never the mutable focus helper. */
#define read_focus fixture_read_focus
#define classify fixture_classify
#include "wb_status_vita.h"
static int sink(void *ctx,const char *p,size_t n){(void)ctx;
    CK(bytes+n<sizeof output);memcpy(output+bytes,p,n);bytes+=n;output[bytes]=0;return 0;}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;int st=0,*status=&st;
    switch(cmd->kind){
    #include "dispatch.inc"
    default:CK(0);return -1;}
}
static void reset(void){
    g_ssh=(fixture_ssh){true,true,true,true,true,true,true,true,false,true};
    a.ctl=true;net_state=net_next=SCE_NETCTL_STATE_CONNECTED;device=0;
    net_rc=dev_rc=net_calls=probes=reads=0;
    e=(FocusEvidence){.tick=5253,.previous_tick=5211,.counters_same=true};
    pub=seal=stored=active=revoked=0;
    unsigned major=0,minor=0;CK(sscanf(WB_VERSION,"%u.%u",&major,&minor)==2 && major<100 && minor<100);
    if(++minor==100){minor=0;++major;}CK(major<100);
    CK(snprintf(next_version,sizeof next_version,"%02u.%02u",major,minor)==5);
    CK(snprintf(pending,sizeof pending,"WBQ2 %s " DIGEST " 2400000\n",next_version)>0);strcpy(private_seal,pending);
}
static void run(const char *line){
    wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={.core_exec=core};wb_out out={NULL,sink};
    bytes=0;output[0]=0;CK(wb_shell_run(&sh,line,&out,&ops)==0);
}
static void has(const char *part){if(!strstr(output,part)){fprintf(stderr,"expected %s, got:\n%s",part,output);exit(2);}}
int main(int argc,char **argv){
    reset();
    if(argc==2){run(argv[1]);fputs(output,stdout);return 0;}
    const char *line="wb-status";
    run(line);const char *expected=
      "OK wb-status version=" WB_VERSION " run=ABABABABABABABAB uptime_ms=1234567890123\n"
      "state wb=running lock=unknown overlay=no foreground=ready focus_reason=ok\n"
      "network link=connected wifi=connected ssh_listener=listening ssh_session=paired\n"
      "update queue=empty target=- standing=disabled\nEND wb-status\n";
    CK(!strcmp(output,expected)&&probes==1&&net_calls==2&&!reads);
    run("wb status");CK(!strcmp(output,expected)&&probes==2);
    wb_cmd raw;CK(!wb_cmd_parse(line,strlen(line),&raw)&&!wb_cmd_parse("wb status",9,&raw));
    const char *bad[]={"wb","wb-status status","wb status --force","wb reset","wb STATUS"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){reset();run(bad[i]);CK(!strcmp(output,"ERR wb-status usage\n")&&!probes&&!net_calls&&!reads);}
    for(int i=0;i<9;i++){reset();bool *gates[]={&g_ssh.authenticated,&g_ssh.accepted,&g_ssh.paired,
        &g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.pty,&g_ssh.sftp,&g_ssh.transport};
        *gates[i]=(i==7);run(line);CK(!strcmp(output,"ERR wb-status no-pty\n")&&!probes&&!net_calls&&!reads);}
    puts("PASS literal command/alias and full negotiated owner PTY only; denied requests sample nothing");

    for(int i=0;i<9;i++){reset();
        if(i==1)e.cb=-1;
        if(i==2)e.power_latched=true;
        if(i==3)e.app_rc=-1;
        if(i==4)e.state.isSystemUiOverlaid=1;
        if(i==5)e.rtc_rc=-1;
        if(i==6)e.tick=0;
        if(i==7)e.counters_same=false;
        if(i==8)e.tick=1;
        static const char *const reason[]={"ok","callback","power","appmgr","overlay","rtc","rtc-zero","counters","rtc-gap"};
        run(line);char buf[50];snprintf(buf,sizeof buf,"focus_reason=%s\n",reason[i]);has(buf);
        has("lock=unknown");CK(probes==1);
        if(i==4)has("overlay=yes foreground=blocked");
        if(i==3)has("overlay=unknown foreground=unknown");
    }
    reset();e.state.isSystemUiOverlaid=7;run(line);has("overlay=unknown");has("lock=unknown");
    puts("PASS nine fresh focus diagnostics, overlay is independent and never relabeled lock");
    reset();device=1;run(line);has("link=connected wifi=not-wifi");
    reset();device=2;run(line);has("link=connected wifi=not-wifi");
    reset();device=9;run(line);has("link=connected wifi=unknown");
    reset();dev_rc=-1;run(line);has("link=connected wifi=unknown");
    reset();net_state=SCE_NETCTL_STATE_DISCONNECTED;run(line);has("link=disconnected wifi=disconnected");
    reset();net_state=SCE_NETCTL_STATE_CONNECTING;run(line);has("link=connecting wifi=unknown");
    reset();net_state=SCE_NETCTL_STATE_FINALIZING;run(line);has("link=finalizing wifi=unknown");
    reset();net_next=SCE_NETCTL_STATE_CONNECTING;run(line);has("link=unknown wifi=unknown");
    reset();net_rc=-1;g_ssh.listening=false;run(line);has("link=unknown wifi=unknown ssh_listener=closed ssh_session=paired");
    puts("PASS SDK link/interface, changing states, unknown device, listener/session separation");
    reset();pub=seal=stored=active=1;run(line);char expected_queue[80];
    snprintf(expected_queue,sizeof expected_queue,"queue=pending target=%s standing=enabled",next_version);
    has(expected_queue);CK(!strstr(output,DIGEST)&&reads==2);
    reset();pub=1;run(line);has("queue=unknown target=- standing=disabled");CK(!reads);
    reset();pub=seal=stored=1;private_seal[11]='1';run(line);has("queue=unknown target=- standing=unknown");
    reset();pub=seal=-1;stored=1;revoked=1;run(line);has("queue=unknown target=- standing=revoked");
    reset();seal=pub=1;pending[7]=private_seal[7]='7';run(line);has("queue=unknown target=-");
    puts("PASS exact marker agreement, unknown on invalid/missing/inconsistent data, no digest/path disclosed");
    return 0;
}
