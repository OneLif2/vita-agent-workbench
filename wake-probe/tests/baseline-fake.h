#ifndef LC_TEST_API
#define LC_TEST_API
#include <stdint.h>
#include <stddef.h>
enum {SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW=2,SCE_DISPLAY_PIXELFORMAT_A8B8G8R8=3,
SCE_DISPLAY_SETBUF_NEXTFRAME=1,SCE_SYSMODULE_BG_APP_UTIL=24,
SCE_CTRL_TRIANGLE=4096,SCE_CTRL_SQUARE=32768,SCE_CTRL_START=8,SCE_O_RDONLY=1,
SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE=0};
typedef struct { int size;void *base;int pitch,pixelformat,width,height; } SceDisplayFrameBuf;
typedef struct { uint64_t timeStamp;uint32_t buttons; } SceCtrlData;
typedef unsigned SceSize;
typedef struct {const char *filePath;void *buf;unsigned bufSize,mode;} SceAppUtilSaveDataFile;
int sceKernelAllocMemBlock(const char*,int,int,void*);
int sceKernelGetMemBlockBase(int,void**);
int sceDisplaySetFrameBuf(SceDisplayFrameBuf*,int);
int sceDisplayWaitSetFrameBuf(void);
int sceSysmoduleLoadModule(int);
int sceCtrlPeekBufferPositive(int,SceCtrlData*,int);
int sceBgAppUtilStartBgApp(int);
uint64_t sceKernelGetSystemTimeWide(void);
int sceIoOpen(const char*,int,int);
int sceIoRead(int,void*,size_t);
int sceIoClose(int);
int sceAppUtilSaveDataDataSave(void*,SceAppUtilSaveDataFile*,int,void*,SceSize*);
#endif
