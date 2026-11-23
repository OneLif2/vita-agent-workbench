#ifndef WP_FAKE_H
#define WP_FAKE_H
#include <stdint.h>
#include <stddef.h>
typedef unsigned SceSize;
typedef struct {int unused;} SceAppUtilInitParam;
typedef struct {int unused;} SceAppUtilBootParam;
typedef struct {uint64_t tick;} SceRtcTick;
typedef struct {const char*filePath;void*buf;unsigned bufSize,mode;} SceAppUtilSaveDataFile;
enum {SCE_O_RDONLY=1,SCE_O_WRONLY=2,SCE_O_CREAT=4,SCE_O_TRUNC=8,SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE=0,SCE_SYSMODULE_BG_APP_UTIL=24};
int sceAppUtilInit(SceAppUtilInitParam*,SceAppUtilBootParam*);
int sceAppUtilSaveDataDataSave(void*,SceAppUtilSaveDataFile*,int,void*,SceSize*);
int sceIoOpen(const char*,int,int);
int sceIoRead(int,void*,unsigned);
int sceIoWrite(int,const void*,unsigned);
int sceIoClose(int);
int sceIoSyncByFd(int,int);
int sceIoRemove(const char*);
int sceRtcGetCurrentTick(SceRtcTick*);
uint64_t sceKernelGetSystemTimeWide(void);
int sceKernelDelayThread(unsigned);
int sceSysmoduleLoadModule(int);
int sceBgAppUtilStartBgApp(int);
int sceAppMgrLaunchAppByUri(int,const char*);
int sceKernelExitProcess(int);
#endif
