#ifndef WB_ID_SIM_IO_H
#define WB_ID_SIM_IO_H
#include <stdint.h>
typedef int SceUID;
typedef unsigned int SceSize, SceMode;
typedef int64_t SceOff;
typedef struct { SceMode st_mode; SceOff st_size; } SceIoStat;
enum { SCE_O_RDONLY=1, SCE_O_WRONLY=2, SCE_O_RDWR=3, SCE_O_APPEND=0x100,
       SCE_O_CREAT=0x200, SCE_O_TRUNC=0x400, SCE_O_EXCL=0x800,
       SCE_S_IFDIR=0010000, SCE_S_IFREG=0020000, SCE_S_IFMT=0170000 };
#define SCE_S_ISDIR(m) (((m)&SCE_S_IFMT)==SCE_S_IFDIR)
#define SCE_S_ISREG(m) (((m)&SCE_S_IFMT)==SCE_S_IFREG)
int sceIoGetstat(const char*, SceIoStat*);
int sceIoMkdir(const char*, SceMode);
int sceIoOpen(const char*,int,SceMode);
int sceIoClose(int);
int sceIoRead(int,void*,unsigned int);
int sceIoWrite(int,const void*,unsigned int);
int sceIoSyncByFd(int,int);
int sceIoSync(const char*,unsigned);
int sceIoRename(const char*,const char*);
#endif
