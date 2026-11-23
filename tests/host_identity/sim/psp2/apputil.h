#ifndef WB_ID_SIM_APPUTIL_H
#define WB_ID_SIM_APPUTIL_H
#include <psp2/io/fcntl.h>
/* Host-side semantic adapter, not target layout. The real cross-build uses VitaSDK. */
typedef struct { unsigned int id; void *slotParam; uint8_t reserved[32]; } SceAppUtilSaveDataFileSlot;
typedef struct { char data[16]; } SceAppUtilSaveDataMountPoint;
typedef struct {
    const char *filePath; void *buf; SceSize bufSize; SceOff offset;
    unsigned int mode, progDelta; uint8_t reserved[32];
} SceAppUtilSaveDataFile;
enum { SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE=0, SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_DIRECTORY=2 };
int sceAppUtilSaveDataDataSave(SceAppUtilSaveDataFileSlot *,SceAppUtilSaveDataFile *,
                              unsigned int,SceAppUtilSaveDataMountPoint *,SceSize *);
#endif
