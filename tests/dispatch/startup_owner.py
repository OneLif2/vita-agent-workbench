"""Exercise the actual 02.18 startup identity branch with local, deterministic stubs.

02.18 (agent-operated): an already enrolled host identity is reused with no
Vita button or on-screen key check; a missing identity is created once (the
owner public pin still comes from mac-public-pin.txt). No R1 path remains.
"""
import pathlib
import shutil
import subprocess
import tempfile

r = pathlib.Path(__file__).resolve().parents[2]
src = (r/"source/vita_ssh_status.c").read_text(encoding="utf-8")
begin, end = "    bool owner_confirmed = false;", "    wb_strcpy(a.pin, sizeof a.pin, g_ssh.host_pin);"
assert src.count(begin) == src.count(end) == 1
guard = src[src.index(begin):src.index(end, src.index(begin))]
assert "await_choice" not in guard and "r1_" not in guard, "02.18 startup must not prompt or use R1"
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define WB_OK 0
static struct { char error[64],host_pin[65]; } g_ssh;
static int intent,marker,remove_rc,complete,prepare_rc,prepares,allowed,removes,quick_ok;
static struct { const char *user_pin; } a={"public-test-pin"};
static bool return_intent_take(void){return intent!=0;}
static bool wb_arm_consume(char accepted[64]){if(marker){removes++;strcpy(accepted,"job-1");}return marker&&remove_rc==0;}
static bool wb_ssh_host_identity_enrolled(void){return complete;}
static int log_event(const char *s){(void)s;return 0;}
static int wb_ssh_prepare(void *s,const char *owner,bool allow){
    assert(s==&g_ssh && owner==a.user_pin);prepares++;allowed=allow;return prepare_rc;
}
static const char *route(void){
    const char *reason=NULL;
    ACTUAL_BRANCH
    (void)consumed;(void)return_intent;
    return NULL;
out: return reason;
}
int main(void){
    int n=0;
    for(intent=0;intent<=1;intent++)
    for(marker=0;marker<=1;marker++)for(remove_rc=-1;remove_rc<=0;remove_rc++)
    for(complete=0;complete<=1;complete++)
    for(prepare_rc=-1;prepare_rc<=0;prepare_rc++){
        prepares=removes=quick_ok=0;allowed=-1;
        const char *reason=route();
        assert(removes==marker && prepares==1);
        assert(allowed==!complete);          /* create only when no identity exists */
        assert(quick_ok==complete);          /* enrolled pair auto-opens the listener */
        assert((reason==NULL)==(prepare_rc==0));
        ++n;
    }
    printf("PASS %d zero-button startup identity paths (actual 02.18 branch, local stubs; no Vita I/O)\n",n);
}
'''
with tempfile.TemporaryDirectory() as d:
    src_file = pathlib.Path(d)/"guard.c"
    exe = pathlib.Path(d)/"guard.exe"
    src_file.write_text(fixture.replace("ACTUAL_BRANCH", guard), encoding="utf-8")
    subprocess.run([shutil.which("gcc") or "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(src_file), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
