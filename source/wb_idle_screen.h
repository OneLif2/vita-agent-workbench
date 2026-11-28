#ifndef WB_IDLE_SCREEN_H
#define WB_IDLE_SCREEN_H
#include <stdbool.h>
#include <stdint.h>

#define WB_SCREEN_IDLE_MS UINT64_C(900000)
#define WB_SCREEN_RETRY_MS UINT64_C(10000)
enum { WB_IDLE_NONE=0, WB_IDLE_OFF=1, WB_IDLE_ON=2 };
typedef struct {
    uint64_t last_activity_ms, retry_after_ms;
    bool initialized, off, wake_pending;
} wb_idle_screen;

/* Local input only. SSH traffic/output never resets this independent clock.
 * off means the platform accepted our display-off request, NOT Sony passcode
 * lock or proof that a physical panel is dark. Never request system suspend. */
static inline int wb_idle_screen_step(wb_idle_screen *s,uint64_t now,
                                      bool activity,bool enabled) {
    if(!s)return WB_IDLE_NONE;
    if(!s->initialized || now<s->last_activity_ms){
        s->initialized=true;s->last_activity_ms=now;s->retry_after_ms=0;
    }
    if(activity)s->last_activity_ms=now;
    if(s->off && (activity || !enabled))s->wake_pending=true;
    if(now<s->retry_after_ms)return WB_IDLE_NONE;
    if(s->off)return s->wake_pending ? WB_IDLE_ON : WB_IDLE_NONE;
    return enabled && now-s->last_activity_ms>=WB_SCREEN_IDLE_MS ? WB_IDLE_OFF : WB_IDLE_NONE;
}
static inline void wb_idle_screen_result(wb_idle_screen *s,uint64_t now,int action,int rc) {
    if(!s || (action!=WB_IDLE_ON && action!=WB_IDLE_OFF))return;
    if(rc>=0){s->off=action==WB_IDLE_OFF;s->retry_after_ms=0;s->wake_pending=false;}
    else s->retry_after_ms=now>UINT64_MAX-WB_SCREEN_RETRY_MS?UINT64_MAX:now+WB_SCREEN_RETRY_MS;
}
#endif
