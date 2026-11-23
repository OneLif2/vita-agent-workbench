#ifndef WB_STUB_PSP2_PROMOTERUTIL_H
#define WB_STUB_PSP2_PROMOTERUTIL_H
#include <psp2/types.h>
typedef enum ScePromoterUtilityPackageType { SCE_PKG_TYPE_VITA = 1, SCE_PKG_TYPE_PSP = 1, SCE_PKG_TYPE_PSM = 3 } ScePromoterUtilityPackageType;
typedef struct ScePromoterUtilityImportParams {
    char path[0x80];
    char titleid[0xC];
    ScePromoterUtilityPackageType type;
    uint32_t attribute;
    char reserved[0x1C];
} ScePromoterUtilityImportParams;
int scePromoterUtilityInit(void);
int scePromoterUtilityExit(void);
int scePromoterUtilityDeletePkg(const char *titleid);
int scePromoterUtilityPromoteImport(ScePromoterUtilityImportParams *params);
int scePromoterUtilityPromotePkg(const char *path, int sync);
int scePromoterUtilityPromotePkgWithRif(const char *path, int sync);
int scePromoterUtilityGetState(int *state);
int scePromoterUtilityGetResult(int *res);
int scePromoterUtilityCheckExist(const char *titleid, int *res);
#endif
