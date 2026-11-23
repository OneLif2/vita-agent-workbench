"""Compile actual physical-review and post-power/bind gate fragments, no Vita I/O."""
from pathlib import Path
import os,subprocess,tempfile
here=Path(__file__).resolve().parent
code=(here.parents[1]/'source/vita_ssh_status.c').read_text(encoding='utf-8')
def between(a,b,start=0):
    i=code.index(a,start);return code[i:code.index(b,i)]
review=between('static void review_return_expected(', 'static int inactive_screen')
gate=between('    if(return_ok){\n        SceCtrlData veto', '    ui_refresh(NULL,',code.index('initial_power_drain(registration,hands_free,quick_ok,return_ok,update_return || quick_ok)'))
assert 'wb_ssh_open' in gate and 'prep_listener' in gate
src=r'''
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#define wb_r1_valid wb_production_r1_valid
#include "wb_review_model.h"
#undef wb_r1_valid
enum {SCE_CTRL_CROSS=1,SCE_CTRL_START=2,SCE_CTRL_SELECT=4,TRIANGLE=8};
typedef struct { unsigned buttons; } SceCtrlData;
typedef struct {char source_run[17],nonce[33];} ticket;
static ticket r1_completed,ret={"1","2"};
enum {WB_Q_LOCAL=1,WB_Q_DIRECT=2,WB_Q_OFFER=3,WB_Q_REMEMBERED=4,Q_REMEMBER=2};
static bool r1_bound,return_ok,quick_ok,update_return;
/* This suite retains strict physical/R1 startup coverage; remote policy has its own suite. */
static const bool remote_start=false;
static int timeline_event(const char *x,const char *y,const char *z){(void)x;(void)y;(void)z;return 0;}
static int qr,qv,qchecks,disabled,bad_pair,quick_audit;
static bool quick_veto(void){return ++qchecks==qv;}
static inline bool remote_start_veto(void){return quick_veto();}
static inline void remote_start_installed_audit(void){}
static int quick_pref(void){return !disabled?Q_REMEMBER:0;}
static bool quick_enabled(void){return !disabled;}
static bool wb_quick_pair(const char*x,const char*y){return x&&y&&!bad_pair;}
static struct {char user_pin[65],run_hex[17];const char *ip;char peer[1][16];int peer_count;} a;
static struct {char host_pin[65];} g_ssh;
static const char *last;
static unsigned pads[4];static int fi,focus_bad,ri,read_bad,expired_at,exp_calls;
static int queued,draw_ok,issue_rc,issued,revoked,audits,audit_ok,prepared,prep_good,net_ok,bind_ok,bound;
static uint64_t ms;static char stage[WBQ_CAP];
static uint64_t now_ms(void){return ms;}
static uint64_t r1_now(void){return 1;}
static bool foreground(bool strict){assert(!strict);return ++fi!=focus_bad;}
static int sceCtrlPeekBufferPositive(int port,SceCtrlData*p,int n){assert(!port&&n==1);
    p->buttons=pads[ri>3?3:ri];return ++ri!=read_bad;}
static void sceKernelDelayThread(int us){assert(us>0);ms+=1000;}
static bool r1_queue(char *r){strcpy(r,stage);return queued;}
static int r1_issue_local(const char*r){assert(!strcmp(r,stage));issued++;return issue_rc;}
static int r1_revoke(void){revoked++;return 0;}
static bool wb_standing_veto(void){return true;}
static void wb_standing_bootstrap(const ticket *t){assert(t==&ret);}
static void ui_refresh(const char*h,const char*s){assert(!h);last=s;}
static bool display_frame_prompt(const char*l,const char*d,int count,const char*p){
    const char *expected="BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB";
    assert(!strcmp(l,"R1 UPDATE 01.34 / INAP00018")&&!strcmp(d,expected)&&!count&&strstr(p,"THIS UPDATE"));
    return draw_ok;
}
static bool log_event(const char*s){if(strstr(s,"R1 RETURN LISTENING"))audits++;if(strstr(s,"QUICK OPEN LISTENING"))quick_audit++;return audit_ok;}
static bool wb_r1_valid(const ticket *t,uint64_t now){assert(t==&ret&&now);return ++exp_calls!=expired_at;}
static const char*prep_listener(void){prepared++;return prep_good?NULL:"OWNER NEEDED";}
static bool net_setup(void){return net_ok;}
static int wb_ssh_open(void*s,const char*ip,int port,const char(*peers)[16],int n){assert(s==&g_ssh&&ip==a.ip&&port==2222&&peers&&n==a.peer_count);bound++;return bind_ok?0:1;}
REVIEW
static const char*start_gate(void){
    const char *reason=NULL;
    GATE
    return NULL;
out:return reason;
}
static void reset(void){ms=0;fi=ri=read_bad=focus_bad=expired_at=exp_calls=0;
    issued=revoked=prepared=audits=bound=issue_rc=0;last="";r1_bound=false;
    quick_ok=false;qr=qv=qchecks=disabled=bad_pair=quick_audit=0;queued=draw_ok=prep_good=net_ok=bind_ok=audit_ok=1;return_ok=false;
    memset(pads,0,sizeof pads);memset(stage,0,sizeof stage);strcpy(stage,"WBQ2 01.34 ");memset(stage+11,'b',64);strcpy(stage+75," 12345\n");}
int main(void){int n=0;
    for(int mode=0;mode<14;mode++){
        reset();pads[0]=TRIANGLE;pads[1]=0;pads[2]=SCE_CTRL_CROSS;
        switch(mode){case 1:pads[0]=pads[1]=pads[2]=pads[3]=SCE_CTRL_CROSS;break;
          case 2:queued=0;break;case 3:focus_bad=1;break;case 4:focus_bad=3;break;
          case 5:read_bad=3;break;case 6:draw_ok=0;break;case 7:pads[2]=SCE_CTRL_SELECT;break;
          case 8:pads[2]=SCE_CTRL_START|SCE_CTRL_CROSS;break;case 9:pads[2]=SCE_CTRL_CROSS|TRIANGLE;break;
          case 10:focus_bad=5;break;case 11:issue_rc=1;break;case 12:case 13:pads[0]=SCE_CTRL_CROSS;break;}
        if(mode==12)review_return_expected("WBQ2 replaced");
        else if(mode==13)review_return_expected(stage); /* held Ã— is not consent; a later release and new Ã— is */
        else review_return_local();
        assert(issued==(mode==0||mode==11||mode==13));assert(revoked==(mode==7||mode==8));
        assert((!strcmp(last,"R1 AUTHORIZED / SELECT REVOKES"))==(mode==0||mode==13));++n;
    }
    for(int mode=0;mode<16;mode++){
        reset();return_ok=(mode!=0&&mode!=1);
        switch(mode){case 1:prep_good=0;break;case 3:expired_at=1;break;case 4:expired_at=2;break;
          case 5:pads[0]=SCE_CTRL_START;break;case 6:pads[1]=SCE_CTRL_SELECT;break;
          case 7:read_bad=1;break;case 8:read_bad=2;break;case 9:focus_bad=1;break;
          case 10:focus_bad=2;break;case 11:net_ok=0;break;case 12:bind_ok=0;break;
          case 13:audit_ok=0;break;case 14:pads[1]=SCE_CTRL_START;break;case 15:pads[0]=SCE_CTRL_SELECT;break;}
        const char*why=start_gate();assert((why==NULL)==(mode==0||mode==2));assert(prepared==(!return_ok));
        assert(r1_bound==(mode==2));assert(audits==(mode==2||mode==13));assert(bound==(mode==0||mode==2||mode==12||mode==13));
        if(mode==2)assert(!memcmp(&ret,&r1_completed,sizeof ret));
        ++n;
    }
    for(int fast=WB_Q_LOCAL;fast<=WB_Q_REMEMBERED;fast++)for(int mode=0;mode<7;mode++){
        reset();qr=fast;quick_ok=true;
        switch(mode){case 1:qv=1;break;case 2:qv=2;break;case 3:bad_pair=1;break;
            case 4:disabled=1;break;case 5:audit_ok=0;break;case 6:focus_bad=2;break;}
        assert((start_gate()==NULL)==(mode==0));
        assert(prepared==0 && !r1_bound && !audits);
        assert(quick_audit==(mode==0||mode==5) && bound==quick_audit);++n;
    }
    printf("PASS %d actual R1 physical review and listener/bind gate paths (host stubs)\n",n);return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)/'gate.c';p.write_text(src.replace('    GATE',gate).replace('REVIEW\nstatic const char',review+'\nstatic const char'),encoding='utf-8')
    exe=Path(tmp)/('gate.exe' if os.name=='nt' else 'gate')
    subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(here.parents[1]/'source'),str(p),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
