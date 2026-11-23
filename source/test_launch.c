#include "launch_gate.h"
#include <assert.h>
int main(void){
    LaunchGate g={0};
    assert(!launch_offer(&g,false,"launch-test",11,500));
    assert(!launch_offer(&g,true,"launch-test extra",17,500));
    assert(!launch_offer(&g,true,"launch-test",11,UINT64_MAX));
    assert(launch_offer(&g,true,"launch-test",11,500));
    assert(!launch_offer(&g,true,"launch-test",11,501));
    assert(launch_poll(&g,true,501,1,1,2)==L_WAIT); /* held Cross */
    assert(launch_poll(&g,true,502,0,1,2)==L_WAIT);
    assert(launch_poll(&g,true,503,3,1,2)==L_WAIT); /* ambiguous */
    assert(launch_poll(&g,true,504,1,1,2)==L_WAIT); /* requires release after ambiguity */
    assert(launch_poll(&g,true,505,0,1,2)==L_WAIT);
    assert(launch_poll(&g,true,506,1,1,2)==L_APPROVED);
    assert(!launch_offer(&g,true,"launch-test",11,510));
    assert(launch_approved_now(&g,true,510));
    assert(!launch_approved_now(&g,false,510));
    assert(!launch_approved_now(&g,true,499));
    assert(!launch_approved_now(&g,true,30500));
    g=(LaunchGate){0};assert(launch_offer(&g,true,"launch-test",11,500));
    assert(launch_poll(&g,true,501,0,1,2)==L_WAIT);
    assert(launch_poll(&g,true,502,2,1,2)==L_CANCELED);
    g=(LaunchGate){0};assert(launch_offer(&g,true,"launch-test",11,500));
    assert(launch_poll(&g,true,501,0,1,2)==L_WAIT);
    assert(launch_poll(&g,true,30500,1,1,2)==L_CANCELED);
    g=(LaunchGate){0};assert(launch_offer(&g,true,"launch-test",11,500));
    assert(launch_poll(&g,false,501,0,1,2)==L_CANCELED);
    g=(LaunchGate){0};assert(launch_offer(&g,true,"launch-test",11,500));
    assert(launch_poll(&g,true,499,0,1,2)==L_CANCELED);
    g=(LaunchGate){0};assert(launch_offer(&g,true,"launch-test",11,500));
    assert(launch_poll(&g,true,501,8,1,2)==L_CANCELED); /* unknown button */
}
