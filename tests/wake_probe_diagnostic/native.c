/* Actual production bridge + parser, with bounded in-memory Vita SDK stubs.
 * No sockets, process exits, real savedata, or platform app launches exist here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include "wb_shell.h"
#include "wb_sha256.h"
#include "wb_vita_io.h"
#include "wb_err.h"
#include "fixture_approval.h"
#define CK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s output=%s\n",__LINE__,#x,output);exit(2);}}while(0)
enum {MODE_B_KEY=2, SCE_O_RDONLY=1,SCE_O_WRONLY=2,SCE_O_CREAT=4,SCE_O_TRUNC=8,SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE=1};
#define SCE_S_ISREG(mode) ((mode)==1)
typedef uint32_t SceSize;
typedef struct{uint32_t st_mode;uint64_t st_size;}SceIoStat;
typedef struct{uint64_t tick;}SceRtcTick;
typedef struct{const char*filePath;void*buf;SceSize bufSize;int mode;}SceAppUtilSaveDataFile;
static struct conn{int authenticated;struct{int accepted,mode;}mode;int session,channel,shell,shell_pty,sftp_ro;}g_ssh;
static struct{char run_hex[17];uint64_t guard_grace;}a;
static bool r1_source_live,r1_bound,r1_signed_armed;
#define WB_PENDING_PATH "private:/pending"
#define WBQ_SEAL "private:/seal"
#define WB_HANDOFF_APP_URI 0x20000
enum{F_NONE,F_STAT,F_OPEN,F_READ,F_WRITE,F_SYNC,F_CLOSE,F_RENAME,F_REMOVE,F_SAVE,F_READBACK,F_MKDIR,F_RNG,F_RNG_ZERO,F_RTC,F_RTC_UNDER,F_CLOCK0,F_MEMBER_SIZE,F_MEMBER_HASH,F_MEMBER_READ,F_MEMBER_OPEN,F_AUDIT,F_LAUNCH,F_EXISTS};
typedef struct{char path[160];unsigned char data[1024];size_t size,pos;bool present;}Mem;
static Mem files[16];static int fault,launches,member_opens,core_calls,wire_status,passes;
static int bad_member_at,late_gate,clock_calls,clock_expire_at;
enum {P_NONE,P_OPEN,P_WRITE,P_WRITE_ZERO,P_SYNC,P_CLOSE,P_READBACK_STAT,P_READBACK_OPEN,
    P_READBACK_READ,P_READBACK_TRAIL,P_READBACK_CLOSE,P_READBACK_SIZE,P_READBACK_CONTENT,
    P_RENAME,P_POST_STAT,P_POST_CONTENT,P_COLLISION,P_RTC2,P_RTC3,P_WRITE_AND_CLOSE,
    P_SYNC_AND_CLOSE,P_CLOSE_AND_REMOVE};
static int pub_fault,temp_mode;static bool publishing,renamed;
static bool network,connected,registry_missing,registry_cases,registry_sha;
static uint64_t fake_now,fake_epoch;
static char output[4096];static size_t used;
static Mem*find(const char*p){for(unsigned i=0;i<16;i++)if(files[i].present&&!strcmp(p,files[i].path))return &files[i];return NULL;}
static Mem*put(const char*p,const void*b,size_t n){Mem*m=find(p);if(!m){for(unsigned i=0;i<16;i++)if(!files[i].present){m=&files[i];break;}}CK(m&&n<=sizeof m->data);memset(m,0,sizeof *m);snprintf(m->path,sizeof m->path,"%s",p);m->present=true;m->size=n;if(n)memcpy(m->data,b,n);return m;}
static bool is_temp(const char*p){return !strcmp(p,"ux0:/data/INAP00018/wake-probe/job.bin.new");}
static bool is_job(const char*p){return !strcmp(p,"ux0:/data/INAP00018/wake-probe/job.bin");}
static int r1_exists(const char*p){if(pub_fault==P_COLLISION&&publishing&&is_job(p))return 1;if(fault==F_EXISTS&&!strcmp(p,"savedata0:/wb-wake-probe-v1.bin"))return -1;return find(p)?1:0;}
static int sceIoGetstat(const char*p,SceIoStat*s){Mem*m=find(p);if(pub_fault==P_READBACK_STAT&&is_temp(p))return -741;if(pub_fault==P_POST_STAT&&renamed&&is_job(p))return -751;if(fault==F_STAT||!m)return -1;s->st_mode=1;s->st_size=m->size+(pub_fault==P_READBACK_SIZE&&is_temp(p));return 0;}
static int sceIoOpen(const char*p,int mode,int perm){(void)perm;if(is_temp(p)){if(mode&SCE_O_WRONLY){publishing=true;if(pub_fault==P_OPEN)return -711;}else if(pub_fault==P_READBACK_OPEN)return -742;temp_mode=mode;}if(fault==F_OPEN)return -1;Mem*m=find(p);if(mode&SCE_O_WRONLY)m=put(p,"",0);if(!m)return -1;m->pos=0;return (int)(m-files)+1;}
static int sceIoRead(int fd,void*p,SceSize n){Mem*m=&files[fd-1];if(pub_fault==P_READBACK_READ&&is_temp(m->path)&&m->pos==0)return -743;if(pub_fault==P_READBACK_TRAIL&&is_temp(m->path)&&m->pos==m->size)return -744;if(fault==F_READ)return -1;size_t k=m->size-m->pos;if(k>n)k=n;memcpy(p,m->data+m->pos,k);if(k&&m->pos==0&&((pub_fault==P_READBACK_CONTENT&&is_temp(m->path))||(pub_fault==P_POST_CONTENT&&renamed&&is_job(m->path))))((unsigned char*)p)[0]^=1;m->pos+=k;return(int)k;}
static int sceIoWrite(int fd,const void*p,SceSize n){Mem*m=&files[fd-1];if(is_temp(m->path)&&(pub_fault==P_WRITE||pub_fault==P_WRITE_AND_CLOSE))return -721;if((is_temp(m->path)&&pub_fault==P_WRITE_ZERO)||fault==F_WRITE)return 0;CK(m->pos+n<=sizeof m->data);memcpy(m->data+m->pos,p,n);m->pos+=n;if(m->size<m->pos)m->size=m->pos;return(int)n;}
static int sceIoClose(int fd){Mem*m=&files[fd-1];if(is_temp(m->path)){if((temp_mode&SCE_O_WRONLY)&&(pub_fault==P_CLOSE||pub_fault==P_WRITE_AND_CLOSE||pub_fault==P_SYNC_AND_CLOSE||pub_fault==P_CLOSE_AND_REMOVE))return -731;if(temp_mode==SCE_O_RDONLY&&pub_fault==P_READBACK_CLOSE)return -745;}return fault==F_CLOSE?-1:0;}
static int sceIoSyncByFd(int fd,int flag){(void)flag;Mem*m=&files[fd-1];if(is_temp(m->path)&&(pub_fault==P_SYNC||pub_fault==P_SYNC_AND_CLOSE))return -725;return fault==F_SYNC?-1:0;}
static int sceIoRemove(const char*p){if(fault==F_REMOVE||(pub_fault==P_CLOSE_AND_REMOVE&&is_temp(p)))return -1;Mem*m=find(p);if(!m)return -1;m->present=false;return 0;}
static int sceIoRename(const char*old,const char*newpath){if(pub_fault==P_RENAME)return -749;if(fault==F_RENAME||find(newpath))return -1;Mem*m=find(old);if(!m)return -1;snprintf(m->path,sizeof m->path,"%s",newpath);renamed=true;return 0;}
static int sceAppUtilSaveDataDataSave(void*x,SceAppUtilSaveDataFile*f,int n,void*y,SceSize*z){(void)x;(void)y;(void)z;CK(n==1);if(fault==F_SAVE)return -1;char p[160];snprintf(p,sizeof p,"savedata0:/%s",f->filePath);Mem*m=put(p,f->buf,f->bufSize);if(fault==F_READBACK)m->data[0]^=1;return 0;}
static uint64_t sceKernelGetSystemTimeWide(void){++clock_calls;if(clock_expire_at&&clock_calls>=clock_expire_at)fake_now+=31000000;return fault==F_CLOCK0?0:fake_now;}
static int sceRtcGetCurrentTick(SceRtcTick*t){if((pub_fault==P_RTC2&&clock_calls==2)||(pub_fault==P_RTC3&&clock_calls==3))return -701;if(fault==F_RTC)return -1;t->tick=fault==F_RTC_UNDER?fake_now-1:fake_now+fake_epoch;return 0;}
static int sceKernelGetRandomNumber(void*p,size_t n){if(fault==F_RNG)return -1;memset(p,fault==F_RNG_ZERO?0:0xab,n);return 0;}
static void hex(char*out,const void*p,size_t n){const unsigned char*b=p;for(size_t i=0;i<n;i++){out[i*2]="0123456789ABCDEF"[b[i]>>4];out[i*2+1]="0123456789ABCDEF"[b[i]&15];}out[n*2]=0;}
static bool wb_standing_owner_pty(void){return g_ssh.authenticated&&g_ssh.mode.accepted&&g_ssh.mode.mode==MODE_B_KEY&&g_ssh.session&&g_ssh.channel&&g_ssh.shell&&g_ssh.shell_pty&&!g_ssh.sftp_ro;}
static bool wb_ssh_connected(const void*p){(void)p;return connected;}
static bool private_link(void){return network;}
static bool log_event(const char*s){CK(strstr(s,"NOT RECEIVER READY"));return fault!=F_AUDIT;}
static uint64_t now_ms(void){return fake_now/1000;}
static int sceAppMgrLaunchAppByUri(int flags,const char*uri){CK(flags==0x20000&&!strcmp(uri,"psgm:play?titleid=WBLC00079"));++launches;return fault==F_LAUNCH?-22:0;}
typedef struct{const char*title,*version,*sha256,*cases;}wb_reg_entry;
static const wb_reg_entry*wb_reg_entry_for(const char*title,const char*ver){static wb_reg_entry row;CK(!strcmp(title,"WBLC00079")&&!strcmp(ver,"01.02"));if(registry_missing)return NULL;row=(wb_reg_entry){title,ver,registry_sha?"bad":FIXTURE_VPK_SHA,registry_cases?"bad":""};return &row;}
static int fixture_read(const void*ctx,uint64_t off,void*out,size_t n){int index=(int)(intptr_t)ctx;if(fault==F_MEMBER_READ)return -1;CK(off+n<=fixture_sizes[index]);memcpy(out,fixture_blobs[index]+off,n);if(fault==F_MEMBER_HASH&&n&&(!bad_member_at||member_opens==bad_member_at))((unsigned char*)out)[0]^=1;return WB_OK;}
int wb_vita_reader_open(const char*p,wb_reader*r,wb_vfile*f){++member_opens;int index=-1;for(int i=0;i<4;i++){char expected[160];snprintf(expected,sizeof expected,"ux0:app/WBLC00079/%s",fixture_paths[i]);if(!strcmp(p,expected))index=i;}CK(index>=0);if((fault==F_MEMBER_OPEN&&(!bad_member_at||member_opens==bad_member_at)))return WB_E_IO;r->ctx=(const void*)(intptr_t)index;r->size=fixture_sizes[index]+(fault==F_MEMBER_SIZE);r->read_at=fixture_read;f->fd=index;return WB_OK;}
void wb_vita_reader_close(wb_vfile*f){(void)f;if(late_gate&&member_opens==12){if(late_gate==1)network=false;if(late_gate==2)g_ssh.authenticated=0;if(late_gate==3)r1_signed_armed=true;if(late_gate==5)r1_bound=true;if(late_gate==4)put(WB_PENDING_PATH,"p",1);}}
int wb_vita_mkdir_p(const char*p){CK(!strcmp(p,"ux0:/data/INAP00018/wake-probe"));return fault==F_MKDIR?WB_E_IO:WB_OK;}
#include "wb_wake_probe_vita.h"
static int sink(void*ctx,const char*s,size_t n){(void)ctx;CK(used+n<sizeof output);memcpy(output+used,s,n);used+=n;output[used]=0;return 0;}
static int guard(const wb_cmd*cmd,wb_out*out,int*status){switch(cmd->kind){
case WB_CMD_TERM_WAKE_PROBE:case WB_CMD_TERM_WAKE_PROBE_STATUS:return wb_probe_command(cmd,out,status);
#include "close.inc"
default:CK(0);return -1;}}
static int core(void*ctx,const wb_cmd*cmd,wb_out*out){(void)ctx;++core_calls;int rc=guard(cmd,out,&wire_status);return rc<0?rc:wire_status;}
static void clear_output(void){output[0]=0;used=0;wire_status=-1;core_calls=0;}
static int run(const char*line){wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};ops.core_exec=core;wb_out out={NULL,sink};return wb_shell_run(&sh,line,&out,&ops);}
static void reset(void){memset(files,0,sizeof files);fault=launches=member_opens=core_calls=bad_member_at=late_gate=clock_calls=clock_expire_at=pub_fault=temp_mode=0;publishing=renamed=false;network=connected=true;registry_missing=registry_cases=registry_sha=false;r1_source_live=r1_bound=r1_signed_armed=false;g_ssh=(struct conn){1,{1,MODE_B_KEY},1,1,1,1,0};memset(&a,0,sizeof a);memcpy(a.run_hex,"1234567890ABCDEF",17);fake_now=1000000000;fake_epoch=1000000000000;clear_output();}
static void pass(const char*label){printf("PASS %s\n",label);++passes;}
static void expect(const char*label,const char*needle,int expected_launches){CK(!run("wake probe job1"));CK(strstr(output,needle)&&launches==expected_launches);pass(label);}
static wp_job pending(void){Mem*m=find(WB_PROBE_PRIVATE_PATH);CK(m&&m->size==sizeof(wp_job));wp_job j;memcpy(&j,m->data,sizeof j);return j;}
static wp_result make_result(void){reset();CK(!run("wake probe job1")&&strstr(output,"DISPATCHED_UNVERIFIED")&&launches==1);wp_job j=pending();wp_result r;wp_result_init(&r,&j);r.stage=WP_STAGE_WORKER_STOP;r.bg_rc=r.return_rc=r.worker_exit_rc=0;r.main_exit_intent=1;r.main_started_us=j.issued_us+1000;r.arm_started_us=j.issued_us+2000;r.first_tick_us=r.arm_started_us;r.last_tick_us=r.first_tick_us+WP_STEP_US*23;r.observed_us=r.last_tick_us;r.max_gap_us=WP_STEP_US;r.tick_count=24;fake_now=r.observed_us+1000;return r;}
static void status_expect(const char*label,wp_result*r,const char*needle){if(r)put(WP_RESULT_PATH,r,sizeof *r);clear_output();int before=launches;CK(!run("wake probe-status"));CK(strstr(output,needle)&&launches==before);pass(label);}
int main(int argc,char**argv){reset();if(argc==3&&!strcmp(argv[1],"--fixture")){
const char*s=argv[2];
const char*names[]={"positive","open","write","write-zero","sync","close","readback-stat","readback-open","readback-read","readback-trailing","readback-close","readback-size","readback-content","rename","postverify-stat","postverify-content","rename-collision","clock-rtc","final-clock-rtc","write-first-error","sync-first-error","close-cleanup-failure"};
bool found=false;for(unsigned i=0;i<sizeof names/sizeof*names;i++)if(!strcmp(s,names[i])){pub_fault=(int)i;found=true;}
if(!strcmp(s,"installed-recheck")){fault=F_MEMBER_OPEN;bad_member_at=5;found=true;}
if(!strcmp(s,"final-installed")){fault=F_MEMBER_OPEN;bad_member_at=9;found=true;}
if(!strcmp(s,"clock-expired")){clock_expire_at=2;found=true;}
if(!strcmp(s,"final-clock-expired")){clock_expire_at=3;found=true;}
CK(found);int rc=run("wake probe job1");fputs(output,stdout);
printf("STATE wire_status=%d launches=%d private=%d public=%d temp=%d member_opens=%d clock_calls=%d\n",wire_status,launches,find(WB_PROBE_PRIVATE_PATH)!=NULL,find(WP_JOB_PATH)!=NULL,find(WB_PROBE_TEMP)!=NULL,member_opens,clock_calls);
return rc<0?2:wire_status;
}if(argc==2){int rc=run(argv[1]);fputs(output,stdout);return rc<0?1:0;}
expect("actual shell dispatch publishes exact private/public nonce job","DISPATCHED_UNVERIFIED",1);CK(member_opens==12);wp_job j=pending();CK(wp_job_live(&j,fake_now,fake_epoch));Mem*m=find(WP_JOB_PATH);CK(m&&!memcmp(m->data,&j,sizeof j));clear_output();CK(!run("pwd")&&!strcmp(output,"ux0:/\n"));pass("probe command does not exit shell");
for(int i=0;i<8;i++){reset();int*gate[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};*gate[i]=(i==7);expect("each paired PTY component is required","no-paired-pty",0);}
reset();connected=false;expect("disconnected transport rejected","no-paired-pty",0);
const char*bad[]={"wake","wake probe","wake probe job1 extra","wake probe-status extra","wake probe a/b","wake probe abcdefghijklmnopqrstuvwxyz1234567","wake other"};for(unsigned i=0;i<sizeof bad/sizeof*bad;i++){reset();CK(!run(bad[i])&&!core_calls&&!launches&&strstr(output,"ERR"));pass("bad shell grammar cannot dispatch");}
wb_cmd raw={.kind=WB_CMD_TERM_WAKE_PROBE,.argc=1};strcpy(raw.argv[0],"job1");for(int i=0;i<8;i++){reset();wb_cmd c=raw;bool*flags[]={&c.force,&c.no_reload,&c.keep_stage,&c.install_after,&c.no_period,&c.promote_now,&c.any_title};if(i<7)*flags[i]=true;else strcpy(c.sha256,"abc");wb_out out={NULL,sink};CK(!wb_probe_command(&c,&out,&wire_status)&&strstr(output,"options-not-accepted")&&!launches);pass("descriptor option cannot bypass shell grammar");}
reset();CK(!wb_cmd_parse("wake probe job1",15,&raw));pass("SSH exec parser cannot dispatch interactive wake probe");
for(int i=0;i<5;i++){reset();if(i==0)r1_source_live=true;if(i==1)r1_signed_armed=true;if(i==2)put(WB_PENDING_PATH,"p",1);if(i==3)put(WBQ_SEAL,"s",1);if(i==4)network=false;expect("active update or absent network rejects probe","busy-or-network",0);}
reset();r1_bound=true;CK(!run("wake probe job1")&&strstr(output,"DISPATCHED_UNVERIFIED")&&launches==1);
reset();late_gate=5;CK(!run("wake probe job1")&&strstr(output,"DISPATCHED_UNVERIFIED")&&launches==1);pass("completed historical R1-bound accepts initial and late admission");
int faults[]={F_CLOCK0,F_RTC,F_RTC_UNDER,F_RNG,F_RNG_ZERO,F_MEMBER_SIZE,F_MEMBER_HASH,F_MEMBER_READ,F_MEMBER_OPEN,F_SAVE,F_READBACK,F_STAT,F_OPEN,F_READ,F_CLOSE,F_MKDIR,F_WRITE,F_SYNC,F_RENAME,F_AUDIT,F_EXISTS};for(unsigned i=0;i<sizeof faults/sizeof*faults;i++){reset();fault=faults[i];expect("SDK/storage/hash admission failure never launches","ERR wake-probe",0);}
for(int member=1;member<=4;member++){reset();fault=F_MEMBER_HASH;bad_member_at=member;expect("each installed member digest is verified","members-not-approved",0);}
for(int phase=5;phase<=9;phase+=4){reset();fault=F_MEMBER_OPEN;bad_member_at=phase;expect("second and final installed-member verification required","ERR wake-probe",0);}
for(int i=0;i<3;i++){reset();if(i==0)registry_missing=true;if(i==1)registry_cases=true;if(i==2)registry_sha=true;expect("registry exact install-only digest required","members-not-approved",0);}
for(int i=1;i<=4;i++){reset();late_gate=i;expect("owner network and update gates rechecked before launch","final-admission",0);CK(!find(WP_JOB_PATH));}
reset();fake_now=UINT64_MAX-100;fake_epoch=1;expect("deadline addition overflow rejected","clock",0);
reset();clock_expire_at=2;expect("long verification cannot use expired job","ERR wake-probe",0);
reset();fault=F_LAUNCH;expect("native launch error is not installed or returned","bootstrap-launch-failed",1);CK(!find(WP_JOB_PATH));
reset();put(WP_JOB_PATH,"collision",9);expect("unknown public job collision preserved","job-path-collision",0);CK(find(WP_JOB_PATH)->size==9);
reset();put(WB_PROBE_PRIVATE_PATH,"bad",3);expect("corrupt private pending never overwritten","private-pending-invalid",0);
reset();expect("initial pending lease","DISPATCHED_UNVERIFIED",1);clear_output();int before=launches;CK(!run("wake probe job2")&&strstr(output,"previous-probe-active")&&launches==before);pass("duplicate pending job never launches twice");
reset();status_expect("no prior job status",NULL,"state=none");
wp_result r=make_result();status_expect("completed public trace is diagnostic only",&r,"DIAGNOSTIC_COMPLETE");CK(strstr(output,"public-untrusted readiness=not-provided close_wb=disabled"));clear_output();CK(!run("close wb")&&strstr(output,"wake-not-ready"));pass("complete diagnostic cannot unlock actual close guard");
r=make_result();r.nonce[0]^=1;status_expect("wrong nonce does not correlate",&r,"INCONCLUSIVE");
r=make_result();a.run_hex[0]='F';status_expect("changed source run is inconclusive",&r,"source-run-changed");
r=make_result();fake_epoch+=3000000;status_expect("reboot or RTC epoch change is inconclusive",&r,"clock-or-boot-fence");
r=make_result();r.tick_count=25;status_expect("count overflow rejected",&r,"INCONCLUSIVE");
r=make_result();put(WP_RESULT_PATH,&r,sizeof r);find(WP_RESULT_PATH)->size--;status_expect("truncated result rejected",NULL,"INCONCLUSIVE");
r=make_result();r.reserved_tail[0]=1;status_expect("result reserved bytes rejected",&r,"INCONCLUSIVE");
r=make_result();r.stage=0;status_expect("zero stage rejected",&r,"INCONCLUSIVE");
r=make_result();r.observed_us=fake_now+1;status_expect("future observation rejected",&r,"timeline-invalid");
r=make_result();r.arm_started_us=r.deadline_us;status_expect("arm past job deadline rejected",&r,"timeline-invalid");
r=make_result();r.arm_started_us=r.main_started_us-1;status_expect("arm cannot precede main start",&r,"timeline-invalid");
r=make_result();r.main_started_us=r.issued_us-1;status_expect("main before issue rejected",&r,"timeline-invalid");
r=make_result();r.max_gap_us=0;status_expect("impossible zero gap cannot complete",&r,"INCONCLUSIVE");
r=make_result();r.last_tick_us+=1000000;r.observed_us=r.last_tick_us;fake_now=r.observed_us+1;status_expect("gap inconsistent with elapsed ticks cannot complete",&r,"INCONCLUSIVE");
r=make_result();r.max_gap_us=10000001;status_expect("large suspension gap cannot complete",&r,"PENDING");
r=make_result();r.bg_rc=-55;status_expect("native BG error is explicit failure",&r,"native-probe-failed");
r=make_result();r.return_rc=-66;status_expect("native return error is explicit failure",&r,"native-probe-failed");
r=make_result();r.worker_exit_rc=-77;status_expect("native worker error is explicit failure",&r,"native-probe-failed");
r=make_result();r.main_exit_intent=2;status_expect("invalid exit intent rejected",&r,"timeline-invalid");
r=make_result();r.first_error_step=999;status_expect("invalid error step rejected",&r,"timeline-invalid");
r=make_result();r.stage=WP_STAGE_WORKER_TICK;r.tick_count=1;r.last_tick_us=r.first_tick_us;r.max_gap_us=0;r.observed_us=r.last_tick_us;r.worker_exit_rc=WP_RC_UNKNOWN;fake_now=r.issued_us+161000000;status_expect("expired incomplete trace is inconclusive",&r,"expired-incomplete");
printf("PASS TOTAL %d actual native bridge/parser cases; no Vita I/O\n",passes);return 0;}
