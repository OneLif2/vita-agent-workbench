#ifndef WB_STUB_PSP2_PHOTOEXPORT_H
#define WB_STUB_PSP2_PHOTOEXPORT_H
#include <psp2/types.h>
typedef struct PhotoExportParam {
    int version;
    const uint32_t *photoTitle, *gameTitle, *gameComment;
    int reserved[8];
} PhotoExportParam;
int scePhotoExportFromData(const void *data, SceSize size,
                           const PhotoExportParam *param, void *workingMemory,
                           void *cancelCb, void *user, char *outPath,
                           SceSize outPathSize);
#endif
