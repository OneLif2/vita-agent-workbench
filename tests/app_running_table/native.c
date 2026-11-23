/* Actual extracted production sweep + dispatcher, deterministic SDK only.
 * No Vita transport, launch, filesystem or UI implementation exists here. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <psp2/appmgr.h>
#include "wb_cmd.h"
#include "wb_out.h"
#include "wb_err.h"
#include "wb_shell.h"
#include "wb_ver.h"
#define CK(x) do { if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(2);} } while(0)
enum { MODE_B_KEY=2 };
static struct {int authenticated;struct {int accepted,mode;} mode;int session,channel,shell,shell_pty,sftp_ro;} g_ssh;
static bool connected=true;
static bool wb_standing_owner_pty(void){return g_ssh.authenticated&&g_ssh.mode.accepted&&g_ssh.mode.mode==MODE_B_KEY&&g_ssh.session&&g_ssh.channel&&g_ssh.shell&&g_ssh.shell_pty&&!g_ssh.sftp_ro;}
static bool wb_ssh_connected(const void *p){(void)p;return connected;}
typedef struct {const char *title,*version,*sha256,*cases;} wb_reg_entry;
static wb_reg_entry wb_reg_entries[32];static size_t compiled_count;
#define WB_REG_ROWS compiled_count
#define WB_APP_LOCAL_ROWS 8
typedef struct {char title[10],ver[6],sha[65];} wb_app_row;
static wb_app_row wb_app_local_rows[WB_APP_LOCAL_ROWS];static unsigned wb_app_local_count;
static const char GOOD_SHA[]="1111111111111111111111111111111111111111111111111111111111111111";
static const char OTHER_SHA[]="2222222222222222222222222222222222222222222222222222222222222222";
static int query_rc,query_pid=4242,api_calls,race_mode;
static char queried[32][10];
static char fixture_titles[32][10],fixture_versions[32][6];
static bool a_connected=true;
static struct {char run_hex[17];} a={{0}};
int sceAppMgrGetIdByName(SceUID *pid,const char *title){
    CK(api_calls<32);snprintf(queried[api_calls++],10,"%s",title);
    if(race_mode==1&&api_calls==1)wb_app_local_count=WB_APP_LOCAL_ROWS+1;
    if(race_mode==2&&api_calls==1)wb_app_local_rows[0].sha[0]='3';
    if(race_mode==3&&api_calls==1)wb_app_local_count=0;
    if(race_mode==4&&api_calls==1)g_ssh.authenticated=0;
    if(race_mode==5&&api_calls==1)connected=false;
    *pid=query_pid;return query_rc;
}
int sceAppMgrGetRunningAppIdListForShell(SceInt32 *p,int n){(void)p;(void)n;return -123;}
SceUID sceAppMgrGetProcessIdByAppIdForShell(SceInt32 p){(void)p;return -123;}
int sceAppMgrGetNameById(SceUID p,char *n){(void)p;(void)n;return -123;}
int sceAppMgrAppParamGetString(int p,int n,char *b,SceSize z){(void)p;(void)n;(void)b;(void)z;return -123;}
#include "wb_app_running_vita.h"
#include "actual_sweep.inc"
static char output[16384];static size_t used;static int wire_status=-1,core_result,write_calls,fail_write;
static int sink(void *ctx,const char *s,size_t n){(void)ctx;++write_calls;if(race_mode==6&&write_calls==1)wb_app_local_count=WB_APP_LOCAL_ROWS+1;if(fail_write&&write_calls==fail_write)return WB_E_IO;CK(used+n<sizeof output);memcpy(output+used,s,n);used+=n;output[used]=0;return 0;}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;int *status=&wire_status;switch(cmd->kind){
#include "actual_dispatch.inc"
default:return WB_E_ARG;}}
static void local(const char *t,const char *v,const char *sha){CK(wb_app_local_count<WB_APP_LOCAL_ROWS);wb_app_row *r=&wb_app_local_rows[wb_app_local_count++];snprintf(r->title,sizeof r->title,"%s",t);snprintf(r->ver,sizeof r->ver,"%s",v);snprintf(r->sha,sizeof r->sha,"%s",sha);}
static void compiled(const char *t,const char *v,const char *sha){CK(compiled_count<32);wb_reg_entries[compiled_count++]=(wb_reg_entry){t,v,sha,""};}
int main(int argc,char **argv){
    CK(argc==2);const char *s=argv[1];bool found=true;
    g_ssh.authenticated=g_ssh.mode.accepted=g_ssh.session=g_ssh.channel=g_ssh.shell=g_ssh.shell_pty=1;g_ssh.mode.mode=MODE_B_KEY;
    connected=a_connected;memcpy(a.run_hex,"1234567890ABCDEF",17);
    compiled("RJGM52237","01.01",GOOD_SHA);
    if(!strcmp(s,"positive")){}
    else if(!strcmp(s,"unknown"))query_rc=-5;
    else if(!strcmp(s,"zero-pid"))query_pid=0;
    else if(!strcmp(s,"negative-pid"))query_pid=-10;
    else if(!strcmp(s,"not-found")){query_rc=(int)0x80802012u;query_pid=0;}
    else if(!strcmp(s,"positive-rc"))query_rc=1;
    else if(!strcmp(s,"duplicate"))local("RJGM52237","01.02",OTHER_SHA);
    else if(!strcmp(s,"duplicate-same-version"))local("RJGM52237","01.01",GOOD_SHA);
    else if(!strcmp(s,"conflict"))local("RJGM52237","01.01",OTHER_SHA);
    else if(!strcmp(s,"compiled-duplicate"))compiled("RJGM52237","01.02",OTHER_SHA);
    else if(!strcmp(s,"runtime-duplicate")){local("RJGM52237","01.02",OTHER_SHA);local("RJGM52237","01.02",OTHER_SHA);}
    else if(!strcmp(s,"runtime-conflict")){local("RJGM52237","01.02",OTHER_SHA);local("RJGM52237","01.02",GOOD_SHA);}
    else if(!strcmp(s,"distinct"))local("WBLC00079","01.02",OTHER_SHA);
    else if(!strcmp(s,"empty"))compiled_count=0;
    else if(!strcmp(s,"runtime-only")){compiled_count=0;local("RJGM52237","01.02",OTHER_SHA);}
    else if(!strcmp(s,"local-overflow"))wb_app_local_count=WB_APP_LOCAL_ROWS+1;
    else if(!strcmp(s,"compiled-overflow"))compiled_count=32;
    else if(!strcmp(s,"combined-overflow")){
        for(unsigned i=1;i<9;i++)compiled("RJGM52237","01.01",GOOD_SHA);
        for(unsigned i=0;i<8;i++)local("WBLC00079","01.02",OTHER_SHA);
    }
    else if(!strcmp(s,"invalid-title"))wb_reg_entries[0].title="bad";
    else if(!strcmp(s,"null-title"))wb_reg_entries[0].title=NULL;
    else if(!strcmp(s,"invalid-version"))wb_reg_entries[0].version="1.01";
    else if(!strcmp(s,"invalid-sha"))wb_reg_entries[0].sha256="bad";
    else if(!strcmp(s,"runtime-invalid")){local("WBLC00079","01.02",OTHER_SHA);memset(wb_app_local_rows[0].title,'X',10);}
    else if(!strcmp(s,"race-count-overflow")){local("WBLC00079","01.02",OTHER_SHA);race_mode=1;}
    else if(!strcmp(s,"race-content")){local("WBLC00079","01.02",OTHER_SHA);race_mode=2;}
    else if(!strcmp(s,"race-count-shrink")){local("WBLC00079","01.02",OTHER_SHA);race_mode=3;}
    else if(!strcmp(s,"race-owner-loss"))race_mode=4;
    else if(!strcmp(s,"race-connection-loss"))race_mode=5;
    else if(!strcmp(s,"race-on-write")){local("WBLC00079","01.02",OTHER_SHA);race_mode=6;}
    else if(!strcmp(s,"worst-metadata")||!strcmp(s,"worst-error-metadata")){
        compiled_count=0;
        for(unsigned i=0;i<8;i++){snprintf(fixture_versions[i],6,"01.%02u",i);compiled("RJGM52237",fixture_versions[i],GOOD_SHA);}
        for(unsigned i=0;i<8;i++){snprintf(fixture_versions[i+8],6,"02.%02u",i);local("RJGM52237",fixture_versions[i+8],OTHER_SHA);}
        if(!strcmp(s,"worst-error-metadata")){query_rc=(int)0x80022005u;query_pid=INT32_MIN;}
    }
    else if(!strcmp(s,"max-unique")){
        compiled_count=0;
        for(unsigned i=0;i<8;i++){snprintf(fixture_titles[i],10,"GAME%05u",i);compiled(fixture_titles[i],"01.01",GOOD_SHA);}
        for(unsigned i=0;i<8;i++){snprintf(fixture_titles[i+8],10,"USER%05u",i);local(fixture_titles[i+8],"01.02",OTHER_SHA);}
    }
    else if(!strcmp(s,"write-fail-first"))fail_write=1;
    else if(!strcmp(s,"write-fail-note"))fail_write=2;
    else if(!strcmp(s,"write-fail-summary"))fail_write=3;
    else if(!strncmp(s,"no-pty-",7)){
        int k=atoi(s+7);int *fields[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
        CK(k>=0&&k<8);*fields[k]=k==7;
    }else if(!strcmp(s,"disconnected"))connected=false;
    else if(strncmp(s,"flag-",5))found=false;
    CK(found);
    wb_cmd cmd={.kind=WB_CMD_TERM_APP_RUNNING,.argc=1};memcpy(cmd.argv[0],"all",4);
    if(!strncmp(s,"flag-",5)){
        int k=atoi(s+5);bool *flags[]={&cmd.force,&cmd.no_reload,&cmd.keep_stage,&cmd.install_after,&cmd.no_period,&cmd.promote_now,&cmd.any_title};
        CK(k>=0&&k<8);if(k<7)*flags[k]=true;else memcpy(cmd.sha256,"x",2);
    }
    wb_out out={NULL,sink};core_result=core(NULL,&cmd,&out);
    fputs(output,stdout);printf("STATE status=%d core_rc=%d calls=%d writes=%d\n",wire_status,core_result,api_calls,write_calls);
    for(int i=0;i<api_calls;i++)printf("QUERY %s\n",queried[i]);
    return core_result<0?2:wire_status;
}
