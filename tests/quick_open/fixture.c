/* Non-deployable native fixture. Production quick route + physical path + power loop. */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "wb_quick_open.h"
#include "startup_power.h"
#include "fresh_choice.h"
/* Local stubs for Vita calls, not network clients. */
typedef int SceSize;
typedef struct {const char*filePath;void*buf;SceSize bufSize;int mode;} SceAppUtilSaveDataFile;
typedef struct {unsigned type;unsigned char dat[1024];} SceAppUtilAppEventParam;
typedef struct{unsigned isSystemUiOverlaid,appEventNum;}SceAppMgrAppState;
static int state_rc,overlay,count_events,unterminated;
static int _sceAppMgrGetAppState(SceAppMgrAppState*s,size_t n,unsigned v){assert(n==sizeof *s&&v);s->appEventNum=count_events;s->isSystemUiOverlaid=overlay;return state_rc;}
typedef struct{unsigned buttons;} SceCtrlData;
enum {SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE=0,SCE_CTRL_START=1,SCE_CTRL_SELECT=2,SCE_CTRL_SQUARE=4,SCE_CTRL_CROSS=8};
#define WB_ARM_MARKER "fixture-s4-pub"
#define WB_ARM_PATH "fixture-s4-private"
#define R1_LOCAL_PATH "fixture-r1-private"
typedef struct{uint8_t bytes[32];} r1_local;
typedef struct{uint8_t bytes[40];} wb_arm_intent;
static struct {char user_pin[65],run_hex[17];unsigned power_calls,power_event;int power_notify_count;bool power_latched;unsigned app_event,sys_event;uint64_t rtc_last;} a;
static const char *actual_host,*present;static int stat_rc,read_rc,optval,nonzero,save_rc,afterwrite;
static bool host_ok,nonempty;
static int app_rc,event_rc,parse_rc,events,parses;
static int r1_exists(const char*p){return present&&!strcmp(p,present)?stat_rc:0;}
static bool r1_get(const char*p,void*d,size_t n){
    if(read_rc<0 || r1_exists(p)!=1)return false;
    memset(d,nonzero?42:0,n);if(n==1)*(uint8_t*)d=(uint8_t)optval;return true;
}
static int sceAppUtilSaveDataDataSave(void*s,SceAppUtilSaveDataFile*f,int count,void*z,int*need){
    assert(!s&&count==1&&!z&&need&&f->bufSize==1&&f->mode==0&&strstr(f->filePath,"quick"));
    if(save_rc>=0){present="savedata0:/wb-quick-pair.bin";stat_rc=1;optval=afterwrite>=0?afterwrite:*(uint8_t*)f->buf;}
    return save_rc;
}
static bool wb_ssh_existing_pin(char d[65]){if(host_ok)strcpy(d,actual_host);return host_ok;}
static int sceAppMgrGetAppParam(char *p){if(app_rc==0)strcpy(p,nonempty?"type=LAUNCH_APP_BY_URI":"");return app_rc;}
static int sceAppUtilReceiveAppEvent(SceAppUtilAppEventParam *e){events++;e->type=7;if(unterminated)memset(e->dat,33,sizeof e->dat);return event_rc;}
static int sceAppUtilAppEventParseLiveArea(const SceAppUtilAppEventParam*e,char*b){parses++;assert(e->type==7&&b);return parse_rc;}
static int pad_rc,power_after,pad_buttons,shows,checks;static uint64_t clk;
static int sceCtrlPeekBufferPositive(int port,SceCtrlData *d,int n){assert(!port&&n==1);d->buttons=(unsigned)pad_buttons;return pad_rc;}
static int r1_settled;
static bool log_event(const char*s){assert(s&&*s);if(!strcmp(s,"R1 POWER ZERO REGISTRATION SETTLED"))r1_settled++;return true;}
static int timeline_event(const char *evt,const char *before,const char *after){(void)evt;(void)before;(void)after;return 0;}
#include "wb_quick_vita.h"
typedef enum {FG_OK,FG_BAD} FocusResult;
typedef struct{int cb,app_rc,rtc_rc;struct{int isSystemUiOverlaid;unsigned appEventNum,systemEventNum;}state;struct{uint64_t tick;}tick;}FocusEvidence;
static int first_cb,focus,ac,susp,low;static bool flip_ac;
static FocusEvidence read_focus(void){FocusEvidence e={0};e.cb=checks++==0?first_cb:0;e.tick.tick=clk+1U;return e;}
static FocusResult focus_result(int cb,int power,int arc,int overlay,int rrc,uint64_t tick,bool cap,bool same,uint64_t last){
    (void)cb;(void)power;(void)arc;(void)overlay;(void)rrc;(void)tick;(void)cap;(void)same;(void)last;return focus?FG_OK:FG_BAD;
}
static int scePowerIsPowerOnline(void){return ac;}
static int scePowerIsSuspendRequired(void){return susp;}
static int scePowerIsLowBattery(void){return low;}
static uint64_t now_ms(void){return clk;}
static void sceKernelDelayThread(int us){clk+=(unsigned)(us/1000);if(power_after && clk>=10)a.power_event=0x80;if(flip_ac && clk>=100)ac=1;}
static bool display_frame_prompt(const char*l,const char*p,int dialog,const char*h){assert(l&&!p&&!dialog&&h);shows++;return false;}
static int diag_writes,diag_fail,diag_disk;
static int wq_save(const char *path,const void *b,size_t n){
    assert(path&&b&&n>0&&n<448);diag_writes++;
    if(diag_fail)return -1;
    if(diag_disk){const char *leaf=strrchr(path,'/');assert(leaf);FILE*f=fopen(leaf+1,"wb");assert(f);assert(fwrite(b,1,n,f)==n);assert(!fclose(f));}
    return 0;
}

#include "drain.inc"
static void reset(void){
    state_rc=overlay=unterminated=0;count_events=1;memset(&a,0,sizeof a);strcpy(a.user_pin,WB_QUICK_OWNER);actual_host=WB_QUICK_HOST;host_ok=true;present=NULL;stat_rc=1;read_rc=0;
    app_rc=event_rc=parse_rc=events=parses=nonempty=0;pad_rc=1;pad_buttons=0;
    r1_settled=0;flip_ac=false;optval=1;afterwrite=-1;save_rc=nonzero=checks=shows=susp=low=ac=power_after=0;focus=1;first_cb=1;clk=0;
    a.power_calls=1;a.power_notify_count=1;
}
int main(int argc,char **argv){
    if(argc==2){
        reset();diag_disk=1;strcpy(a.run_hex,"0123456789ABCDEF");strcpy(pw_diag_source,"FEDCBA9876543210");
        bool r1=true,pair=false,ok_expected=false,auto_pair=false;
        if(!strcmp(argv[1],"quick-flags")){r1=false;pair=true;a.power_event=0x20000000;}
        else if(!strcmp(argv[1],"manual-low")){r1=false;low=1;}
        else if(!strcmp(argv[1],"manual-ui")){r1=false;}
        else if(!strcmp(argv[1],"r1-focus")){focus=0;}
        else if(!strcmp(argv[1],"r1-sink-fail")){diag_fail=1;a.power_event=WB_AFTER_RESUME;}
        else if(!strcmp(argv[1],"r1-suspend")){susp=1;}
        else if(!strcmp(argv[1],"healthy")){ok_expected=true;a.power_calls=0;a.power_notify_count=0;first_cb=0;}
        else if(!strcmp(argv[1],"r1-ack")){a.power_event=WB_AFTER_RESUME;}
        else if(!strcmp(argv[1],"r1-settled-zero")){ok_expected=true;}
        else if(!strcmp(argv[1],"paired-auto-healthy")){auto_pair=pair=true;r1=false;ok_expected=true;}
        else if(!strcmp(argv[1],"paired-auto-focus")){auto_pair=pair=true;r1=false;focus=0;}
        else if(!strcmp(argv[1],"paired-auto-power")){auto_pair=pair=true;r1=false;a.power_event=0x20000000;}
        else if(!strcmp(argv[1],"paired-auto-suspend")){auto_pair=pair=true;r1=false;susp=1;}
        else if(!strcmp(argv[1],"paired-auto-low")){auto_pair=pair=true;r1=false;low=1;}
        else{return 2;}
        bool ok=initial_power_drain(0,r1||auto_pair,pair,r1,r1||pair)==NULL;printf("allowed=%d write_attempts=%d\n",(int)ok,diag_writes);
        if(auto_pair){assert(shows==0);printf("paired-auto local_prompts=%d\n",shows);}
        assert(ok==ok_expected && diag_writes==!ok_expected);return 0;
    }

int count=0;
    for(int mode=0;mode<29;mode++){reset();wb_quick_route expect=WB_Q_LOCAL;
        switch(mode){
            case 0:expect=WB_Q_DIRECT;break;
            case 1:actual_host=WB_QUICK_OWNER;expect=WB_Q_NONE;break;
            case 2:strcpy(a.user_pin,WB_QUICK_HOST);expect=WB_Q_NONE;break;
            case 3:host_ok=false;expect=WB_Q_NONE;break;
            case 4:present=WB_Q_OPT_PATH;optval=0;expect=WB_Q_NONE;break;
            case 5:present=WB_Q_OPT_PATH;stat_rc=-1;expect=WB_Q_NONE;break;
            case 6:present=WB_PENDING_PATH;break;case 7:present=WBQ_SEAL;break;case 8:present=WB_R1_INTENT;break;
            case 9:present=WB_R1_SUCCESS;break;case 10:present=WBQ_TEST;break;case 11:present=WB_ARM_MARKER;break;
            /* 01.51+: stale spent savedata alone, no public pending marker. */
            case 12:present=R1_LOCAL_PATH;nonzero=1;expect=WB_Q_DIRECT;break;case 13:present=WB_ARM_PATH;read_rc=-1;expect=WB_Q_DIRECT;break;
            case 14:present=WB_ARM_PATH;expect=WB_Q_DIRECT;break;
            case 15:nonempty=true;break;case 16:app_rc=-1;break;case 17:event_rc=-1;break;
            case 18:parse_rc=-1;break;case 19:present=R1_LOCAL_PATH;stat_rc=-1;expect=WB_Q_DIRECT;break;
            case 20:count_events=0;expect=WB_Q_REMEMBERED;break;
            case 21:count_events=0;present=WB_Q_OPT_PATH;optval=Q_REMEMBER;expect=WB_Q_REMEMBERED;break;
            case 22:count_events=0;present=WB_Q_OPT_PATH;optval=Q_FENCE;expect=WB_Q_REMEMBERED;break;
            case 23:count_events=0;state_rc=-1;break;case 24:count_events=0;overlay=1;break;
            case 25:present=WB_Q_OPT_PATH;optval=Q_FENCE;break;case 26:unterminated=1;break;
            case 27:count_events=0;present=WB_Q_OPT_PATH;optval=Q_REMEMBER;nonempty=true;expect=WB_Q_REMEMBERED;break;
            case 28:count_events=0;present=WB_Q_OPT_PATH;optval=9;expect=WB_Q_NONE;break;
        }
        wb_quick_route got=quick_route();if(got!=expect)fprintf(stderr,"mode %d expected %d got %d\n",mode,(int)expect,(int)got);assert(got==expect);assert(parses==(mode==0||mode==12||mode==13||mode==14||mode==18||mode==19||mode==25));count++;
    }
    reset();assert(quick_write(Q_REMEMBER));count_events=0;assert(quick_route()==WB_Q_REMEMBERED);count++;
    assert(quick_barrier()&&quick_pref()==Q_FENCE&&quick_route()==WB_Q_REMEMBERED);count++;
    assert(quick_barrier()&&quick_pref()==Q_FENCE);count++;
    reset();save_rc=-1;assert(!quick_barrier());count++;
    reset();assert(quick_switch(false)&&!quick_enabled()&&quick_switch(true)&&quick_enabled());count++;
    afterwrite=0;assert(!quick_switch(true)&&!quick_enabled());count++;
    save_rc=-1;assert(!quick_switch(true)&&!quick_enabled());count++;
    reset();assert(!quick_veto());pad_buttons=SCE_CTRL_START;assert(quick_veto());pad_buttons=SCE_CTRL_SELECT;assert(quick_veto());pad_rc=0;pad_buttons=0;assert(quick_veto());count+=4;
    for(int mode=0;mode<13;mode++){reset();bool pair=true,unattended=false,ok=false;
        switch(mode){case 0:ok=true;break;case 1:pair=false;break;case 2:a.power_event=0x80;break;case 3:susp=1;break;
        case 4:low=1;break;case 5:first_cb=0;break;case 6:a.power_calls=2;break;case 7:ac=1;break;
        case 8:focus=0;break;case 9:power_after=1;break;case 10:pair=false;unattended=true;break;case 11:unattended=true;ok=true;break;case 12:unattended=true;a.power_event=0x80;break;}
        assert((initial_power_drain(0,unattended,pair,false,false)==NULL)==ok);assert(shows==(mode==1||mode==2));count++;
    }
    /* Prior suite still exercises the no-proof shape (unattended=true,
     * paired=false, return_ok=false) and the unchanged physical manual path. */
    for(int mode=0;mode<17;mode++) {
        reset();bool proof=true,unattended=true,ok=false;unsigned expected_prompts=0;
        switch(mode){
          case 0:ok=true;break; /* first-sample zero registration, 320ms quiet */
          case 1:a.power_event=WB_AFTER_RESUME;break;
          case 2:a.power_event=WB_AFTER_RESUME|WB_BATTERY_ONLINE;break;
          case 3:susp=1;break;
          case 4:low=1;break;
          case 5:focus=0;break;
          case 6:a.power_event=0x20000000;break;
          case 7:a.power_calls=2;break;
          case 8:first_cb=0;break;
          case 9:power_after=1;break;
          case 10:proof=false;break;
          case 11:unattended=false;proof=false;expected_prompts=1;break;
          case 12:flip_ac=true;break;
          case 13:clk=21;break;
          case 14:a.power_notify_count=2;break;
          case 15:a.power_calls=0;a.power_notify_count=0;first_cb=0;ok=true;break;
          case 16:unattended=false;expected_prompts=1;break;
        }
        assert((initial_power_drain(0,unattended,false,proof,false)==NULL)==ok);
        assert(r1_settled==(mode==0));assert((unsigned)shows==expected_prompts);
        if(mode==0)assert(clk>=POWER_FIRST_MS+POWER_QUIET_MS);
        count++;
    }
    printf("PASS %d paired-origin, opt-out, changed identity, stale return, veto and power paths (actual production guards + SDK stubs; no device).\n",count);return 0;
}
