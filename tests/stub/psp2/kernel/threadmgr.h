#ifndef WB_STUB_PSP2_KERNEL_THREADMGR_H
#define WB_STUB_PSP2_KERNEL_THREADMGR_H
#include <psp2/types.h>
typedef int (*SceKernelCallbackFunction)(int notifyId, int notifyCount, int notifyArg, void *common);
uint64_t sceKernelGetProcessTimeWide(void);
void sceKernelDelayThread(SceUInt usec);
SceUID sceKernelCreateCallback(const char *name, unsigned int attr, SceKernelCallbackFunction func, void *arg);
int sceKernelDeleteCallback(SceUID cb);
int sceKernelCheckCallback(void);
#endif
