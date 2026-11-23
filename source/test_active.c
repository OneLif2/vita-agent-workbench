#include <assert.h>
#include "active_terminal.h"
#include "status_gate.h"
static int closed;
static void stop(void){closed++;}
int main(void){
    const uint64_t at=180001;
    assert(active_check(true,false,true,stop)==ACTIVE_GO && closed==0);
    StatusGate late_peer={.running=true,.authenticated=true,.deadline=at+120000};
    assert(gate_status(&late_peer,at,"status",6)==1);
    assert(gate_status(&late_peer,at+1,"status",6)==2);
    assert(!gate_status(&late_peer,at+120000,"status",6));
    assert(permit_state(false,false,0,3)==PERMIT_READY);
    assert(permit_state(true,true,3,3)==PERMIT_READY);
    assert(permit_state(false,true,1,3)==PERMIT_OWNER_ENDED);
    assert(permit_state(true,false,3,3)==PERMIT_ATTEMPTS_SPENT);
    assert(active_check(true,false,false,stop)==ACTIVE_GUARD_LOST && closed==1);
    assert(active_check(true,true,false,stop)==ACTIVE_USER_EXIT && closed==2);
    assert(active_check(false,false,false,stop)==ACTIVE_INPUT_ERROR && closed==3);
}
