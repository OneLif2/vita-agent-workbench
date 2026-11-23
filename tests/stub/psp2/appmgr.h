#ifndef WB_STUB_PSP2_APPMGR_H
#define WB_STUB_PSP2_APPMGR_H
#include <psp2/types.h>
typedef struct SceAppMgrAppState {
    SceUInt32 systemEventNum;
    SceUInt32 appEventNum;
    int isSystemUiOverlaid;
    unsigned char reserved[116];
} SceAppMgrAppState;
typedef struct SceAppMgrExecOptParam { int reserved[64]; } SceAppMgrExecOptParam;
int _sceAppMgrGetAppState(SceAppMgrAppState *state, SceSize len, uint32_t version);
int __sceAppMgrGetAppState(SceAppMgrAppState *state, SceUInt32 len, SceUInt32 version);
int sceAppMgrLoadExec(const char *appPath, char *const argv[], const SceAppMgrExecOptParam *opt);
int sceAppMgrLaunchAppByUri(int flags, const char *uri);
int sceAppMgrLaunchAppByName2(const char *name, const char *param, void *opt);
int sceAppMgrDestroyOtherApp(void);
int _sceAppMgrContentInstallPeriodStart(void);
int _sceAppMgrContentInstallPeriodStop(void);
/* Non-shell per-title query: the real symbol takes an 0x80-byte info block. */
int sceAppMgrGetAppInfo(const char *name, SceAppMgrAppState *info);
int sceAppMgrGetIdByName(SceUID *pid, const char *name);
int sceAppMgrGetRunningAppIdListForShell(SceInt32 *appIds, int count);
#endif
