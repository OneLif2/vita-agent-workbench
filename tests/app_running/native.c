/* Production read-only inventory module + interactive shell, SDK stubs only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "wb_shell.h"
#include <psp2/appmgr.h>
static char output[8192];static size_t used;
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s output=%s\n",__LINE__,#x,output);exit(2);}}while(0)
enum{MODE_B_KEY=2};
static struct{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static struct{char run_hex[17];}a;
static bool connected;
static bool wb_standing_owner_pty(void){return g_ssh.authenticated&&g_ssh.mode.accepted&&g_ssh.mode.mode==MODE_B_KEY&&g_ssh.session&&g_ssh.channel&&g_ssh.shell&&g_ssh.shell_pty&&!g_ssh.sftp_ro;}
static bool wb_ssh_connected(const void*x){(void)x;return connected;}
#include "wb_ver.h"
#include "wb_app_running_vita.h"
static int first_n,second_n,lists,pids,titles,names,calls,status,passes,probes,known_calls,known_rc;
static SceInt32 first_ids[8],second_ids[8];
static int pid_mode,title_mode,name_mode,known_pid=4242,unsafe_calls;
int sceAppMgrGetRunningAppIdListForShell(SceInt32*out,int count){
    if(count==1){++probes;return 0;}int n=lists?second_n:first_n;const SceInt32*ids=lists?second_ids:first_ids;++lists;if(n>0)for(int i=0;i<n&&i<count;i++)out[i]=ids[i];return n;}
SceUID sceAppMgrGetProcessIdByAppIdForShell(SceInt32 id){++pids;if(pid_mode==1)return -55;if(pid_mode==2&&pids>first_n)return -66;if(pid_mode==3&&pids>first_n)return 9000+id;if(pid_mode==4)return 0;return 1000+id;}
int sceAppMgrGetNameById(SceUID pid,char*out){++titles;if(title_mode==1)return -77;if(title_mode==2){memset(out,'X',32);return 0;}if(title_mode==3){strcpy(out,"bad\033id");return 0;}if(title_mode==4){strcpy(out,"INAP00018-oversize");return 0;}if(title_mode==5){strcpy(out,"\xc3\xa9");return 0;}if(title_mode==6&&titles>first_n){strcpy(out,"PCSG99999");return 0;}strcpy(out,pid==1001?"INAP00018":"PCSG00001");return 0;}
int sceAppMgrGetIdByName(SceUID*out,const char*name){++known_calls;CK(name&&strlen(name)==9);            /* any well-formed title id is legal here */
if(known_rc){*out=0;return known_rc;}
if(strcmp(name,WB_TITLE_ID)){*out=0;return -2139086830;}  /* 0x80802012 NOT_FOUND */
*out=known_pid;return 0;}
/* These trap-only fixture symbols are NOT declarations of verified raw ABIs.
 * The candidate must never reference them. Legacy signatures below exist only
 * to run the immutable old header's same-input transaction, not as SDK truth. */
#ifdef WB_FIXTURE_LEGACY_RAW
int _sceAppMgrGetStatusByName(const char*name,void*st){(void)name;(void)st;++unsafe_calls;return (int)0x80022005u;}
int _sceAppMgrGetPidListForShell(SceUID*pids,int count){(void)pids;(void)count;++unsafe_calls;return (int)0x80022005u;}
#else
int _sceAppMgrGetStatusByName(void){++unsafe_calls;return (int)0x80022005u;}
int _sceAppMgrGetPidListForShell(void){++unsafe_calls;return (int)0x80022005u;}
#endif
/* Match the real public wrapper's TWO-argument declaration, not a mock
 * three-argument API. It must also remain uncalled in the candidate. */
int sceAppMgrGetAppInfo(const char*name,SceAppMgrAppState*info){(void)name;(void)info;++unsafe_calls;return (int)0x8080201fu;}
int sceAppMgrAppParamGetString(int pid,int param,char*out,SceSize length){(void)pid;++names;CK(param==10&&length==64);if(name_mode==1)return -88;if(name_mode==2){memset(out,'Z',length);return 0;}if(name_mode==3){strcpy(out,"bad\033[31m");return 0;}if(name_mode==4){strcpy(out,"\xe4\xb8\xad\xe6\x96\x87");return 0;}if(name_mode==5){out[0]=0;return 0;}if(name_mode==6){strcpy(out,"bad\"quoted");return 0;}if(name_mode==7){memset(out,'a',63);out[63]=0;return 0;}strcpy(out,"Sample Game");return 0;}static int sink(void*ctx,const char*s,size_t n){(void)ctx;CK(used+n<sizeof output);memcpy(output+used,s,n);used+=n;output[used]=0;return 0;}
static int core(void*ctx,const wb_cmd*c,wb_out*out){(void)ctx;++calls;return wb_app_running_command(c,out,&status);}
static int run(const char*line){wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};ops.core_exec=core;wb_out out={NULL,sink};return wb_shell_run(&sh,line,&out,&ops);}
static void reset(void){
    known_pid=4242;unsafe_calls=0;memset(output,0,sizeof output);used=0;first_n=second_n=2;lists=pids=titles=names=calls=pid_mode=title_mode=name_mode=probes=known_calls=known_rc=0;status=-1;memset(first_ids,0,sizeof first_ids);memset(second_ids,0,sizeof second_ids);first_ids[0]=second_ids[0]=1;first_ids[1]=second_ids[1]=2;g_ssh.authenticated=g_ssh.mode.accepted=g_ssh.session=g_ssh.channel=g_ssh.shell=g_ssh.shell_pty=1;g_ssh.mode.mode=MODE_B_KEY;g_ssh.sftp_ro=0;connected=true;memcpy(a.run_hex,"1234567890ABCDEF",17);}
static void pass(const char*s){printf("PASS %s\n",s);++passes;}
static void expect(const char*label,const char*needle,int semantic){CK(!run("ps"));CK(strstr(output,needle)&&status==semantic);CK(unsafe_calls==0);CK(!strchr(output,27));pass(label);}
int main(int argc,char**argv){reset();
if(argc==3&&!strcmp(argv[1],"--fixture")){
    const char *input=argv[2],*command="app running INAP00018";
    if(!strcmp(input,"zero-pid"))known_pid=0;
    else if(!strcmp(input,"negative-pid"))known_pid=-99;
    else if(!strcmp(input,"unknown"))known_rc=-5;
    else if(!strcmp(input,"not-found"))command="app running VSSH00001";
    else if(!strcmp(input,"list-denied")){first_n=(int)0x8080201cu;command="ps";}
    else if(strcmp(input,"positive"))return 2;
    int rc=run(command);fputs(output,stdout);
    printf("STATE semantic_status=%d lists=%d known_queries=%d unsafe_calls=%d\n",status,lists,known_calls,unsafe_calls);
    return rc<0?2:status;
}
if(argc==2){int rc=run(argv[1]);fputs(output,stdout);return rc<0?1:0;}
expect("typed ps queries two AppMgr app records","TWO_SAMPLE_SNAPSHOT",0);CK(lists==2&&pids==4&&titles==4&&names==2&&calls==1);CK(strstr(output,"app_id=1 pid=1001 title_id=INAP00018")&&strstr(output,"foreground=unknown scope=appmgr-started-apps"));
reset();CK(!run("app running")&&strstr(output,"TWO_SAMPLE_SNAPSHOT")&&calls==1);pass("app running is the same typed paired-PTY alias");
reset();{wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};char completed[WB_SH_LINE];CK(wb_shell_complete(&sh,"ps",&ops,completed)&&!strcmp(completed,"ps "));}second_ids[0]=2;second_ids[1]=1;expect("list order is not a false state transition","TWO_SAMPLE_SNAPSHOT",0);
reset();first_n=second_n=0;expect("true empty two-sample result is scoped not API denial","count=0",0);CK(!pids&&!titles&&!names);
reset();first_n=-123;expect("denied initial API is literal error not empty list","rc=-123",1);CK(lists==1&&probes==1&&known_calls==1&&!strstr(output,"count=0"));CK(strstr(output,"capacity=1 rc=0")&&strstr(output,"pid=4242 identity=observed")&&strstr(output,"symbol=unknown"));CK(strstr(output,"probe=GetAppInfo state=not-probed reason=abi-unverified"));
CK(strstr(output,"probe=GetStatusByName state=not-probed reason=abi-unverified"));
CK(strstr(output,"probe=GetPidListForShell state=not-probed reason=abi-unverified"));
CK(unsafe_calls==0);CK(!strstr(output,"is_running="));
reset();first_n=(int)0x8080201CU;expect("unpublished 0x8080201C is reported raw and stays unknown","symbol=unknown",1);CK(strstr(output,"rc=-2139086820 (0x8080201C)"));
reset();first_n=(int)0x8080201FU;expect("published NOEXEC is named without inventing a cause","symbol=NOEXEC",1);
reset();first_n=-123;known_rc=-5;expect("known-title identity error is unknown not absent","pid=0 identity=unknown",1);CK(strstr(output,"GetIdByName title=INAP00018 rc=-5"));
reset();second_n=-124;expect("denied second API never claims stable list","rc=-124",1);CK(!strstr(output,"TWO_SAMPLE_SNAPSHOT"));
reset();first_n=9;expect("native returned count overflow is rejected","invalid-or-overflow",1);CK(!pids);
reset();second_n=9;expect("second count overflow rejected","invalid-or-overflow",1);
reset();first_n=second_n=8;for(int i=0;i<8;i++)first_ids[i]=second_ids[i]=i+1;expect("full capacity may be truncated and is inconclusive","potentially_truncated=yes",1);int lines=0;for(char*p=output;*p;p++)lines+=*p=='\n';CK(lines==10);
reset();first_ids[1]=first_ids[0];expect("duplicate IDs rejected before pid query","invalid-or-overflow",1);CK(!pids);
reset();first_ids[0]=0;expect("zero app ID rejected","invalid-or-overflow",1);
reset();first_ids[0]=-1;expect("negative app ID rejected","invalid-or-overflow",1);
reset();second_ids[1]=second_ids[0];expect("duplicate second list IDs rejected","invalid-or-overflow",1);
reset();second_ids[1]=3;expect("changed app IDs are not a stable snapshot","changing-snapshot",1);
reset();second_n=1;expect("disappearing app count is inconclusive","changing-snapshot",1);
reset();pid_mode=1;expect("PID query denied is unknown with native rc","rc=-55",1);CK(strstr(output,"pid=0 title_id=unknown"));
reset();pid_mode=2;expect("disappeared PID cannot retain stale title","pid=0 title_id=unknown",1);
reset();pid_mode=3;expect("recycled PID cannot retain stale title","pid=0 title_id=unknown",1);
reset();pid_mode=4;expect("zero PID is not a valid process","pid=0 title_id=unknown",1);
for(int i=1;i<=6;i++){reset();title_mode=i;expect("denied non-NUL invalid or changed title is unknown","title_id=unknown",1);}
for(int i=1;i<=6;i++){reset();name_mode=i;expect("denied non-NUL control Unicode empty quoted name is not projected","name_sfo10=\"unknown\"",1);}
reset();name_mode=7;expect("maximum terminated ASCII title text remains bounded","TWO_SAMPLE_SNAPSHOT",0);
for(int i=0;i<8;i++){reset();int*gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};*gate[i]=(i==7);expect("each negotiated owner PTY prerequisite is required","no-paired-pty",1);CK(!lists);}
reset();connected=false;expect("disconnected transport never queries platform","no-paired-pty",1);CK(!lists);
const char*bad[]={"ps anything","ps --force","app running anything","app running --force","ps | ls","ps;ver","app running token","PS","app Running"};for(unsigned i=0;i<sizeof bad/sizeof*bad;i++){reset();CK(!run(bad[i])&&!calls&&!lists&&strstr(output,"ERR"));pass("invalid inventory grammar never reaches platform");}
for(int i=0;i<8;i++){reset();wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING};bool*f[]={&c.force,&c.no_reload,&c.keep_stage,&c.install_after,&c.no_period,&c.promote_now,&c.any_title};if(i<7)*f[i]=true;else strcpy(c.sha256,"x");wb_out out={NULL,sink};CK(!wb_app_running_command(&c,&out,&status)&&status==1&&!lists);pass("injected descriptor flags rejected without SDK calls");}
reset();{wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING,.argc=2};wb_out out={NULL,sink};CK(!wb_app_running_command(&c,&out,&status)&&status==1&&!lists);}pass("two operands still rejected");
reset();{wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING,.argc=1};memcpy(c.argv[0],"INAP00018",10);wb_out out={NULL,sink};used=0;output[0]=0;CK(wb_app_running_command(&c,&out,&status)==0&&status==0&&!lists&&known_calls==1);CK(strstr(output,"state=started pid=4242 source=GetIdByName"));}reset();known_rc=-2139086830;{wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING,.argc=1};memcpy(c.argv[0],"VSSH00001",10);wb_out out={NULL,sink};used=0;output[0]=0;CK(!wb_app_running_command(&c,&out,&status)&&status==1);CK(strstr(output,"state=not-started rc=-2139086830 (0x80802012) symbol=NOT_FOUND"));}reset();first_n=-123;{wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING};wb_out out={NULL,sink};used=0;output[0]=0;
CK(wb_app_running_command(&c,&out,&status)==0&&status==1);CK(unsafe_calls==0);
CK(strstr(output,"GetStatusByName state=not-probed reason=abi-unverified"));
CK(strstr(output,"GetPidListForShell state=not-probed reason=abi-unverified"));}
pass("unverified raw and AppInfo probes are explicitly skipped with zero unsafe calls");
pass("a definite NOT_FOUND is named and reported as not started");
pass("one exact title is answered by GetIdByName only");
for(int value=0;value<2;value++){reset();known_pid=value?-99:0;CK(!run("app running INAP00018")&&status==1);
CK(strstr(output,"state=unknown")&&strstr(output,"symbol=INVALID_RESULT")&&!strstr(output,"state=not-started")&&known_calls==1&&!unsafe_calls);
pass("rc zero with invalid PID is unknown not absence");}
const int errors[]={-5,(int)0x80802000u,(int)0x8080201fu,(int)0x8080201cu,(int)0x80022005u};
for(unsigned i=0;i<sizeof errors/sizeof *errors;i++){reset();known_rc=errors[i];CK(!run("app running INAP00018")&&status==1);
CK(strstr(output,"state=unknown")&&!strstr(output,"state=not-started")&&known_calls==1&&!unsafe_calls);pass("only NOT_FOUND is classified not started");}
for(int invalid=0;invalid<4;invalid++){reset();wb_cmd c={.kind=WB_CMD_TERM_APP_RUNNING,.argc=1};
if(invalid==0){strcpy(c.argv[0],"all");}
else if(invalid==1){strcpy(c.argv[0],"inap00018");}
else if(invalid==2){strcpy(c.argv[0],"INAP00018X");}
else{memset(c.argv[0],'A',sizeof c.argv[0]);}
wb_out out={NULL,sink};CK(!wb_app_running_command(&c,&out,&status)&&status==1&&!known_calls&&!lists&&!unsafe_calls);pass("injected malformed title descriptors rejected before platform");}
reset();{wb_cmd c={.kind=WB_CMD_VER};wb_out out={NULL,sink};CK(!wb_app_running_command(&c,&out,&status)&&status==1&&!known_calls&&!lists&&!unsafe_calls);}pass("wrong injected command kind fails common admission");
reset();{wb_cmd c2;CK(!wb_cmd_parse("ps",2,&c2)&&!wb_cmd_parse("app running",11,&c2));}pass("raw exec parser cannot reach ps or app running");
printf("PASS TOTAL %d actual app-running module/parser checkpoints; no Vita I/O\n",passes);return 0;}
