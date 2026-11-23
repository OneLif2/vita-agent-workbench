#ifndef WB_STUB_PSP2_IO_FCNTL_H
#define WB_STUB_PSP2_IO_FCNTL_H
#include <psp2/types.h>
enum {
    SCE_O_RDONLY = 0x0001, SCE_O_WRONLY = 0x0002,
    SCE_O_RDWR = SCE_O_RDONLY | SCE_O_WRONLY,
    SCE_O_APPEND = 0x0100, SCE_O_CREAT = 0x0200,
    SCE_O_TRUNC = 0x0400, SCE_O_EXCL = 0x0800
};
SceUID sceIoOpen(const char *file, int flags, SceMode mode);
int sceIoClose(SceUID fd);
int sceIoRead(SceUID fd, void *data, SceSize size);
int sceIoWrite(SceUID fd, const void *data, SceSize size);
SceOff sceIoLseek(SceUID fd, SceOff offset, int whence);
int sceIoSyncByFd(SceUID fd, int unknown);
int sceIoSync(const char *device, unsigned int unknown);
#endif
