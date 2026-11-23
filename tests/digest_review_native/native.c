/* Actual command and seal-review model. No device, status/grant/apply, file or network I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_shell.h"
#include "wb_review_model.h"
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
enum{MODE_B_KEY=2};
static struct conn{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static struct{char run_hex[17];}a;
static int reads,tree,fault,app_rc,failed_write;
static char receipt[WBQ_CAP],result[512];static size_t used;
#define HASH "0123456789abcdef89abcdef7654321000001111aaaa9999ffeeddcc44332211"
#define GROUPS "01234567 89ABCDEF 89ABCDEF 76543210 00001111 AAAA9999 FFEEDDCC 44332211"
#define RUN "ABCDEF123456789A"
#define EXPECT "OK r1-review model=local-review title=INAP00018 target=01.82 bytes=2473832 source_run=" RUN "\ngroups=" GROUPS "\n"
static int wq_sealed_receipt(const char *pending,const char *seal,char *out){
    CK(!strcmp(pending,WB_PENDING_PATH)&&!strcmp(seal,WBQ_SEAL));
    ++reads;if(fault==1 || (fault==4&&reads==2))return WB_E_IO;
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
static void reset(void){g_ssh=(struct conn){1,{1,MODE_B_KEY},1,1,1,1,0};strcpy(a.run_hex,RUN);
    strcpy(receipt,"WBQ2 01.82 " HASH " 2473832\n");used=0;result[0]=0;reads=tree=fault=failed_write=0;app_rc=-1;}
static int run(const char *line){wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};ops.core_exec=core;
    wb_out o={NULL,sink};return wb_shell_run(&sh,line,&o,&ops);}
static bool bad_reader(char r[WBQ_CAP]){memset(r,'a',WBQ_CAP);return true;}
int main(int argc,char **argv){
    reset();if(argc==2){int rc=run(argv[1]);fputs(result,stdout);return rc<0?1:0;}
    CK(run("r1-review")==0&&!strcmp(result,EXPECT)&&app_rc==0&&reads==2&&tree==1);
    wb_review_model model;reset();CK(wb_review_snapshot(&model,r1_queue));
    CK(!strcmp(model.groups,GROUPS)&&!strcmp(model.label,"R1 UPDATE 01.82 / INAP00018")&&model.bytes==2473832&&
       !strcmp(model.receipt,receipt)&&strlen(model.groups)==71);
    puts("PASS real shell+descriptor, all eight ordered local screen groups and exact receipt");
    for(int i=0;i<8;i++){reset();int *gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
        *gate[i]=(i==7);CK(run("r1-review")==0&&!strcmp(result,"ERR r1-review no-pty\n")&&app_rc==1&&!reads&&!tree);}
    wb_cmd c;CK(!wb_cmd_parse("r1-review",9,&c)||c.kind!=WB_CMD_TERM_R1_REVIEW);
    reset();CK(!run("r1-review authorize")&&!strcmp(result,"ERR r1-review usage\n")&&!reads);
    reset();wb_out out={NULL,sink};c=(wb_cmd){.kind=WB_CMD_TERM_R1_REVIEW,.argc=1};
    CK(!adapter(&c,&out,&app_rc)&&app_rc==1&&!reads);
    puts("PASS eight negotiated SSH gates, raw exec rejection, operands/approval impossible");
    for(int i=1;i<=4;i++){reset();fault=i;CK(!run("r1-review")&&app_rc==1&&!strcmp(result,"ERR r1-review not-verified\n"));}
    puts("PASS missing seal, invalid tree, changing seal, final seal read error: never partial groups");
    for(int i=0;i<8;i++){reset();char *where=receipt+11+i*8;*where='?';
        CK(!run("r1-review")&&app_rc==1&&!strcmp(result,"ERR r1-review not-verified\n"));}
    const char *bad[]={"WBQ1 01.82","WBQ2 1.082 " HASH " 5\n","WBQ2 01.82 " HASH " 0\n",
                       "WBQ2 01.82 " HASH " 00042\n","WBQ2 01.82 " HASH " 1234","WBQ2 01.82 " HASH " 9999999999\n"};
    for(size_t i=0;i<sizeof bad/sizeof *bad;i++){reset();strcpy(receipt,bad[i]);CK(!run("r1-review")&&app_rc==1&&!strcmp(result,"ERR r1-review not-verified\n"));}
    CK(!wb_review_snapshot(&model,bad_reader));
    reset();a.run_hex[0]='g';CK(!run("r1-review")&&app_rc==1&&!reads);
    reset();failed_write=1;CK(run("r1-review")<0&&app_rc==1);
    puts("PASS every digest group, malformed version/byte counts, missing LF/NUL, invalid source/run and output fault");
    return 0;
}
