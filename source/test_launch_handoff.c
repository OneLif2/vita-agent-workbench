#include "launch_handoff.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
static char observed[16];
static size_t n;
static unsigned after_calls;
static bool pre_ok,post_first_ok,post_last_ok,offline;
static int32_t rc;
static void event(char c){assert(n<sizeof observed-1); observed[n++]=c;observed[n]=0;}
static bool before(void){event('B');return pre_ok;}
static void stop(void){event('S');offline=true;}
static bool after(void){event('A');return offline&&(after_calls++?post_last_ok:post_first_ok);}
static void note(void){event('N');}
static int32_t call(void){event('C');assert(offline);return rc;}
static void reset(bool b,bool first,bool last){
    observed[0]=0;n=after_calls=0;offline=false;
    pre_ok=b;post_first_ok=first;post_last_ok=last;
}
int main(void){
    const LaunchOps ops={before,stop,after,note,call};
    reset(false,true,true);
    assert(launch_handoff(&ops).phase==LH_PRE_GUARD_STOP&&!strcmp(observed,"B"));
    reset(true,false,true);
    assert(launch_handoff(&ops).phase==LH_POST_GUARD_STOP&&!strcmp(observed,"BSA"));
    reset(true,true,false);
    assert(launch_handoff(&ops).phase==LH_POST_GUARD_STOP&&!strcmp(observed,"BSANA"));
    reset(true,true,true);rc=(int32_t)UINT32_C(0x8080201f);
    LaunchHandoff done=launch_handoff(&ops);
    assert(done.phase==LH_CALLED&&done.rc==rc&&!strcmp(observed,"BSANAC"));
    assert(launch_reply(rc,UINT32_C(0x8080201f))==LH_NOEXEC);
    assert(launch_reply(-1,UINT32_C(0x8080201f))==LH_OTHER);
    assert(launch_reply(0,UINT32_C(0x8080201f))==LH_ACK);
}
