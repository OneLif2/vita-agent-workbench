#ifndef WB_SIGNED_FOCUS_H
#define WB_SIGNED_FOCUS_H

#include <stdbool.h>
#include <stdint.h>

/* Bounded single-operation verification, not a replacement global focus
 * policy. Both endpoint samples must come from the same live local process. */
enum { WB_SIGNED_FOCUS_BUDGET_US=10000000, WB_SIGNED_FOCUS_SKEW_US=200000 };
typedef struct {
    uint64_t rtc_us,mono_us;
    uint32_t app_events,system_events,power_generation;
} wb_signed_focus;
static inline bool wb_signed_focus_interval(const wb_signed_focus *a,const wb_signed_focus *b) {
    if(b->app_events!=a->app_events || b->system_events!=a->system_events ||
       b->power_generation!=a->power_generation || !a->rtc_us ||
       b->rtc_us<a->rtc_us || b->mono_us<a->mono_us)return false;
    const uint64_t wall=b->rtc_us-a->rtc_us, mono=b->mono_us-a->mono_us;
    return wall<=WB_SIGNED_FOCUS_BUDGET_US && mono<=WB_SIGNED_FOCUS_BUDGET_US &&
           ((wall==0)==(mono==0)) &&
           (wall>mono?wall-mono:mono-wall)<=WB_SIGNED_FOCUS_SKEW_US;
}

#endif
