/* Exact production descriptor and production seal checks with no real device. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_shell.h"
#include "wb_r1_notice.h"
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
enum{MODE_B_KEY=2};
static struct conn{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static struct{char run_hex[17];uint32_t power_calls;}a;
static wb_r1_notice r1_notice;
static bool r1_source_live,r1_bound,focused;
static int reads,tree,fault,app_rc,failed_write,notices;
static char receipt[WBQ_CAP],result[512];static size_t used;static uint64_t tm;
#define HASH "0123456789abcdef89abcdef7654321000001111aaaa9999ffeeddcc44332211"
#define RUN "ABCDEF123456789A"
#define COMMAND "r1-notice " HASH
#define EXPECT "OK r1-notice title=INAP00018 target=01.83 bytes=2473832 source_run=" RUN " manifest=" HASH "\n"
static uint64_t now_ms(void){return tm;}
static bool foreground(bool strict){CK(!strict);return focused;}
static void ui_refresh(const char *a0,const char *s){CK(!a0&&!strcmp(s,"UPDATE RECEIVED / LOCAL APPROVAL"));++notices;}
static int wq_sealed_receipt(const char *pending,const char *seal,char *out){
    CK(!strcmp(pending,WB_PENDING_PATH)&&!strcmp(seal,WBQ_SEAL));
    ++reads;if(fault==1||(fault==4&&reads==2))return WB_E_IO;
    memcpy(out,receipt,WBQ_CAP);if(fault==3&&reads==2)out[11]=out[11]=='a'?'b':'a';
    return WB_OK;
}
static int queued_core_check(void){++tree;return fault==2?WB_E_STATE:WB_OK;}
#include "queue.inc"
static int sink(void *ctx,const char *s,size_t n){(void)ctx;if(failed_write)return -1;
    CK(used+n<sizeof result);memcpy(result+used,s,n);used+=n;result[used]=0;return 0;}
static int adapter(const wb_cmd *cmd,wb_out *out,int *status){switch(cmd->kind){
#include "dispatch.inc"
    default:CK(0);return -1;}}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;int rc=adapter(cmd,out,&app_rc);return rc<0?rc:app_rc;}
static void clear_reply(void){used=0;result[0]=0;app_rc=-1;}
static void reset(void){g_ssh=(struct conn){1,{1,MODE_B_KEY},1,1,1,1,0};strcpy(a.run_hex,RUN);
    strcpy(receipt,"WBQ2 01.83 " HASH " 2473832\n");clear_reply();reads=tree=fault=failed_write=notices=0;
    r1_source_live=r1_bound=false;focused=true;r1_notice=(wb_r1_notice){0};tm=160;a.power_calls=3;}
static int run(const char *line){wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};ops.core_exec=core;
    wb_out o={NULL,sink};return wb_shell_run(&sh,line,&o,&ops);}
int main(int argc,char **argv){
    reset();if(argc==2){int rc=run(argv[1]);fputs(result,stdout);return rc<0?1:0;}
    CK(run(COMMAND)==0&&!strcmp(result,EXPECT)&&app_rc==0&&reads==2&&tree==1&&notices==1);
    CK(r1_notice.pending&&!strcmp(r1_notice.receipt,receipt)&&!r1_source_live&&!r1_bound);
    CK(!wb_notice_ready(&r1_notice,true,true,tm+10,3)&&r1_notice.pending);
    CK(wb_notice_ready(&r1_notice,false,true,tm+11,3)&&!r1_notice.pending);
    CK(!wb_notice_ready(&r1_notice,false,true,tm+12,3));
    clear_reply();CK(!run(COMMAND)&&!strcmp(result,"ERR r1-notice busy\n")&&reads==2&&notices==1);
    puts("PASS received title/version/bytes and one exact auto-presentation after disconnect; no grant");
    for(int i=0;i<8;i++){reset();int *gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
        *gate[i]=(i==7);CK(!run(COMMAND)&&!strcmp(result,"ERR r1-notice no-pty\n")&&app_rc==1&&!reads&&!tree&&!r1_notice.pending);}
    wb_cmd c;CK(!wb_cmd_parse(COMMAND,strlen(COMMAND),&c)||c.kind!=WB_CMD_TERM_R1_NOTICE);
    const char *bad[]={"r1-notice","r1-notice short","r1-notice " HASH " extra","r1-notice F" HASH,
                       "r1-notice 0123456789Abcdef89abcdef7654321000001111aaaa9999ffeeddcc44332211"};
    for(unsigned k=0;k<sizeof bad/sizeof *bad;k++){reset();CK(!run(bad[k])&&!strcmp(result,"ERR r1-notice usage\n")&&!reads&&!notices);}
    puts("PASS negotiated paired PTY needed; malformed, extra or noncanonical input ignored");
    for(int i=1;i<=4;i++){reset();fault=i;CK(!run(COMMAND)&&app_rc==1&&!strcmp(result,"ERR r1-notice not-verified\n")&&!r1_notice.pending&&!notices);}
    for(unsigned g=0;g<8;g++){reset();char req[]=COMMAND;req[10u+8u*g]=req[10u+8u*g]=='a'?'b':'a';
        CK(!run(req)&&app_rc==1&&!strcmp(result,"ERR r1-notice mismatch\n")&&!r1_notice.pending&&!notices);}
    reset();failed_write=1;CK(run(COMMAND)<0&&app_rc==1&&!r1_notice.pending&&!notices);
    for(int i=0;i<3;i++){reset();if(i==0)r1_source_live=true;if(i==1)r1_bound=true;if(i==2)focused=false;
        CK(!run(COMMAND)&&app_rc==1&&!strcmp(result,"ERR r1-notice busy\n")&&!reads&&!notices);}
    puts("PASS changed tree or seal, all eight digest groups, lost output and unsafe approval state rejected");
    for(int i=0;i<5;i++){reset();CK(!run(COMMAND)&&r1_notice.pending);
        if(i==4)wb_notice_cancel(&r1_notice); /* local SELECT */
        CK(!wb_notice_ready(&r1_notice,false,i!=0,i==2?tm-1:i==3?tm+WB_NOTICE_TTL_MS:tm,i==1?4:3)&&!r1_notice.pending);
        CK(!wb_notice_ready(&r1_notice,false,true,tm+1,3));
        clear_reply();CK(!run(COMMAND)&&!strcmp(result,"ERR r1-notice busy\n"));}
    puts("PASS focus/power/clock/timeout/cancel lose deferred presentation without granting approval");
    return 0;
}
