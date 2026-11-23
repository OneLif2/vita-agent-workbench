#ifndef WB_STUB_PSP2_KERNEL_RNG_H
#define WB_STUB_PSP2_KERNEL_RNG_H
#include <psp2/types.h>
int sceKernelGetRandomNumber(void *buffer, SceSize size);
#endif
