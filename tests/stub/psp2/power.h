#ifndef WB_STUB_PSP2_POWER_H
#define WB_STUB_PSP2_POWER_H
#include <psp2/types.h>
int scePowerRegisterCallback(SceUID cbid);
int scePowerUnregisterCallback(SceUID cbid);
int scePowerIsPowerOnline(void);
int scePowerIsSuspendRequired(void);
int scePowerGetBatteryLifePercent(void);
int scePowerGetBatteryTemp(void);
int scePowerIsBatteryCharging(void);
int scePowerIsLowBattery(void);
#endif
