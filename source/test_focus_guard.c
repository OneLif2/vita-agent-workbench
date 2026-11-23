#include <assert.h>
#include "focus_guard.h"
#define SNAP(cb,power,app,overlay,rtc,tick) focus_result(cb,power,app,overlay,rtc,tick,true,false,0)
int main(void){
    assert(SNAP(-1,0,0,false,0,2)==FG_CB_ERR);
    assert(SNAP(0,0x00100000,0,true,0,2)==FG_POWER);
    assert(SNAP(0,0x00010000,0,true,0,2)==FG_POWER);
    assert(SNAP(0,0x00001000,0,false,0,2)==FG_POWER);
    assert(SNAP(0,0,-4,true,0,2)==FG_APPMGR_ERR);
    assert(SNAP(0,0,0,true,-1,2)==FG_RTC_ERR);
    assert(SNAP(0,0,0,true,0,0)==FG_RTC_ZERO);
    assert(SNAP(0,0,0,true,0,2)==FG_OVERLAY);
    assert(SNAP(1,0,0,false,0,2)==FG_OK);
    assert(focus_result(0,0,0,false,0,3,false,false,2)==FG_COUNTERS);
    assert(focus_result(0,0,0,false,0,1,false,true,2)==FG_RTC_GAP);
    assert(focus_result(0,0,0,false,0,1500003,false,true,2)==FG_RTC_GAP);
    assert(focus_result(0,0,0,false,0,1500002,false,true,2)==FG_OK);
}
