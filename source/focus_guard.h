#ifndef INA_FOCUS_GUARD
#define INA_FOCUS_GUARD
#include <stdint.h>
#include <stdbool.h>
typedef enum { FG_OK,FG_CB_ERR,FG_POWER,FG_APPMGR_ERR,FG_OVERLAY,FG_RTC_ERR,FG_RTC_ZERO,FG_COUNTERS,FG_RTC_GAP } FocusResult;
static inline FocusResult focus_result(int cb,uint32_t power,int app,bool overlay,int rtc,uint64_t tick,
                                      bool capture,bool counters_same,uint64_t previous_tick){
    if(cb<0)return FG_CB_ERR;
    if(power)return FG_POWER;
    if(app<0)return FG_APPMGR_ERR;
    if(rtc<0)return FG_RTC_ERR;
    if(!tick)return FG_RTC_ZERO;
    if(overlay)return FG_OVERLAY;
    if(!capture&&!counters_same)return FG_COUNTERS;
    if(!capture&&(tick<previous_tick||tick-previous_tick>UINT64_C(1500000)))return FG_RTC_GAP;
    return FG_OK;
}
#endif
