/* Real shell + extracted production guard. The build links no exit/launch,
 * R1, pending, arbitrary target, observer, or Vita I/O stubs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_shell.h"
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
enum { MODE_B_KEY=2 };
static struct conn{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static int calls,wire_status;
static char output[512];
static size_t used;
static int sink(void *ctx,const char *s,size_t n){(void)ctx;
    CK(used+n<sizeof output);memcpy(output+used,s,n);used+=n;output[used]=0;return 0;}
static int guard(const wb_cmd *cmd,wb_out *out,int *status){switch(cmd->kind){
#include "close.inc"
    default:CK(0);return -1;}}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;++calls;
    int rc=guard(cmd,out,&wire_status);return rc<0?rc:wire_status;}
static void reset(void){g_ssh=(struct conn){1,{1,MODE_B_KEY},1,1,1,1,0};output[0]=0;used=0;calls=0;wire_status=-1;}
static int run(wb_shell_engine *sh,const char *line){wb_shell_ops ops={0};ops.core_exec=core;
    wb_out out={NULL,sink};return wb_shell_run(sh,line,&out,&ops);}
int main(int argc,char **argv){
    wb_shell_engine sh;wb_shell_init(&sh);reset();
    if(argc==2){int rc=run(&sh,argv[1]);fputs(output,stdout);return rc<0?1:0;}
    CK(!run(&sh,"close wb")&&calls==1&&wire_status==1&&!strcmp(output,"ERR close-wb wake-not-ready\n"));
    /* Deliberately exercise the same shell immediately; no close/quit state. */
    reset();CK(!run(&sh,"pwd")&&!strcmp(output,"ux0:/\n")&&!calls);
    puts("PASS requested close with no verified wake receiver fails closed; shell remains open");
    for(int i=0;i<8;i++){reset();int *gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
        *gate[i]=(i==7);CK(!run(&sh,"close wb")&&calls==1&&wire_status==1&&!strcmp(output,"ERR close-wb no-pty\n"));}
    puts("PASS all eight negotiated authentication/paired/live PTY conditions");
    const char *bad[]={"close","close Vita","close INAP00018","close wb --force","close wb token","close WB","close wb 1234","close wb ready","close wb 192.0.2.1","close 'wb --safe'"};
    wb_cmd c;
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){reset();CK(!run(&sh,bad[i])&&!calls&&!strcmp(output,"ERR close-wb usage: close wb\n"));CK(!wb_cmd_parse(bad[i],strlen(bad[i]),&c));}
    CK(!wb_cmd_parse("close wb",8,&c));
    reset();c=(wb_cmd){.kind=WB_CMD_TERM_CLOSE_WB,.argc=1};wb_out out={NULL,sink};
    CK(!guard(&c,&out,&wire_status)&&wire_status==1&&!strcmp(output,"ERR close-wb usage: close wb\n"));
    puts("PASS literal target only; raw exec cannot dispatch or forward into payload");
    reset();CK(run(&sh,"exit")==1&&!strcmp(output,"Bye.\n")&&!calls);
    puts("PASS ordinary exit still closes only the shell");
    return 0;
}
