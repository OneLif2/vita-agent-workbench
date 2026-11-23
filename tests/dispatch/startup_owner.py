"""Exercise the actual startup approval branch with local, deterministic UI/FS stubs."""
import pathlib
import shutil
import subprocess
import tempfile

r = pathlib.Path(__file__).resolve().parents[2]
src = (r/"source/vita_ssh_status.c").read_text(encoding="utf-8")
begin, end = "    bool owner_confirmed = false;", "    wb_strcpy(a.pin, sizeof a.pin, g_ssh.host_pin);"
assert src.count(begin) == src.count(end) == 1
guard = src[src.index(begin):src.index(end, src.index(begin))]
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define WB_ROOT "ux0:data/INAP00018"
#define SCE_CTRL_CROSS 1
#define WB_OK 0
static struct { char error[64],host_pin[65]; } g_ssh;
static struct {char host_pin[65];} ret;
static int return_ok,intent;
static bool return_intent_take(void){return intent!=0;}
enum {WB_Q_NONE,WB_Q_LOCAL,WB_Q_DIRECT,WB_Q_OFFER,WB_Q_REMEMBERED,SCE_CTRL_SQUARE=4,Q_REMEMBER=2};
static int qr,quick_ok,veto,square_ok,square_asked,quick_pin_bad;
static bool remote_start;
static bool wb_quick_pair(const char *a,const char *b){return a && b && !quick_pin_bad;}
static bool quick_veto(void){return veto!=0;}
static inline bool remote_start_veto(void){return quick_veto();}
static bool wb_r1_pin_equal(const char *a,const char *b){return strlen(a)==64 && !strcmp(a,b);}
static struct { const char *user_pin; } a={"public-test-pin"};
static int marker,remove_rc,complete,approval,prepare_rc,asked,prepares,allowed,removes;
static bool wb_arm_consume(char accepted[64]){if(marker){removes++;strcpy(accepted,"job-1");}return marker&&remove_rc==0;}
static bool wb_ssh_host_identity_enrolled(void){return complete;}
static int log_event(const char *s){(void)s;return 0;}
static void startup_mark(const char *s,int n){(void)s;(void)n;}
static int await_choice(const char *s,const char *p,int button,int ms){
    if(button==SCE_CTRL_SQUARE){assert(!p&&(!strcmp(s,"SQUARE OPENS PAIRED SSH")||!strcmp(s,"SQUARE REMEMBERS PAIRED START")) && ms>0);square_asked++;return square_ok;}
    assert(!strcmp(s,"CHECK MAC PUBLIC PIN") && p==a.user_pin && button==1 && ms>0);
    asked++;return approval;
}
static int wb_ssh_prepare(void *s,const char *owner,bool allow){
    assert(s==&g_ssh && owner==a.user_pin);prepares++;allowed=allow;return prepare_rc;
}
static const char *route(void){
    const char *reason=NULL;
    (void)remote_start;
    ACTUAL_BRANCH
    return NULL;
out: return reason;
}
int main(void){
    int n=0;memset(ret.host_pin,'A',64);memcpy(g_ssh.host_pin,ret.host_pin,65);
    for(return_ok=0;return_ok<=1;return_ok++)
    for(intent=0;intent<=1;intent++)
    for(marker=0;marker<=1;marker++)for(remove_rc=-1;remove_rc<=0;remove_rc++)
    for(complete=0;complete<=1;complete++)for(approval=0;approval<=1;approval++)
    for(prepare_rc=-1;prepare_rc<=0;prepare_rc++){
        asked=prepares=removes=0;allowed=-1;
        const char *reason=route();
        bool must_ask=!(return_ok || ((intent || (marker && remove_rc==0)) && complete));
        bool can_prepare=!must_ask || approval;
        assert(removes==marker && asked==must_ask && prepares==can_prepare);
        assert(allowed==(can_prepare?(int)must_ask:-1));
        assert((reason==NULL)==(can_prepare && prepare_rc==0));
        ++n;
    }
    intent=marker=approval=complete=prepare_rc=0;return_ok=1;g_ssh.host_pin[0]='B';
    assert(!strcmp(route(),"R1 HOST CHANGED"));++n;
    for(qr=WB_Q_LOCAL;qr<=WB_Q_REMEMBERED;qr++)for(square_ok=0;square_ok<2;square_ok++)
    for(veto=0;veto<2;veto++)for(quick_pin_bad=0;quick_pin_bad<2;quick_pin_bad++){
        return_ok=marker=approval=asked=prepares=square_asked=quick_ok=0;allowed=-1;
        const char *why=route();
        assert(square_asked==0);
        assert(asked==0 && (prepares==0 || allowed==0));
        bool ok=!veto && !quick_pin_bad;
        assert((why==NULL)==ok);++n;
    }
    printf("PASS %d foreground authorization paths (actual startup branch, local stubs; no Vita I/O)\n",n);
}
'''
with tempfile.TemporaryDirectory() as d:
    src_file=pathlib.Path(d)/"guard.c"
    exe=pathlib.Path(d)/"guard.exe"
    src_file.write_text(fixture.replace("ACTUAL_BRANCH",guard), encoding="utf-8")
    subprocess.run([shutil.which("gcc") or "gcc","-std=c11","-Wall","-Wextra","-Werror",str(src_file),"-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
