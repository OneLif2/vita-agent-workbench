#ifndef WB_STUB_PSP2_KERNEL_PROCESSMGR_H
#define WB_STUB_PSP2_KERNEL_PROCESSMGR_H
#include <psp2/types.h>
void sceKernelExitProcess(int res);
enum { SCE_KERNEL_POWER_TICK_DEFAULT = 0, SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND = 0x10 };
int sceKernelPowerTick(int type);
uint64_t sceKernelGetProcessTimeWide(void);
#endif
