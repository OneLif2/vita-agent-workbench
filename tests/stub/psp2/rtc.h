#ifndef WB_STUB_PSP2_RTC_H
#define WB_STUB_PSP2_RTC_H
#include <psp2/types.h>
typedef struct SceRtcTick { uint64_t tick; } SceRtcTick;
int sceRtcGetCurrentTick(SceRtcTick *tick);
int sceRtcGetTick(const SceDateTime *dt, SceRtcTick *tick);
#endif
