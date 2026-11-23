#ifndef WB_STUB_PSP2_KERNEL_MODULEMGR_H
#define WB_STUB_PSP2_KERNEL_MODULEMGR_H
#include <psp2/types.h>
SceUID sceKernelLoadStartModule(const char *path, SceSize args, void *argp, int flags, void *option, int *status);
SceUID sceKernelLoadModule(const char *path, int flags, void *option);
int sceKernelStartModule(SceUID modid, SceSize args, void *argp, int flags, void *option, int *status);
int sceKernelStopModule(SceUID modid, SceSize args, void *argp, int flags, void *option, int *status);
int sceKernelUnloadModule(SceUID modid, int flags, void *option);
int sceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, int flags, void *option, int *status);
#endif
