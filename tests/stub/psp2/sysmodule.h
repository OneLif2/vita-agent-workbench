#ifndef WB_STUB_PSP2_SYSMODULE_H
#define WB_STUB_PSP2_SYSMODULE_H
#include <psp2/types.h>
typedef enum SceSysmoduleModuleId {
    SCE_SYSMODULE_NET = 0x000A,
    SCE_SYSMODULE_CTRL = 0x0010,
    SCE_SYSMODULE_POWER = 0x0012,
    SCE_SYSMODULE_PHOTO_EXPORT = 0x0016,
    SCE_SYSMODULE_DISPLAY = 0x0017,
    SCE_SYSMODULE_APPUTIL = 0x0021,
    SCE_SYSMODULE_GXM = 0x0026,
    SCE_SYSMODULE_PROMOTER_UTIL = 0x0029,
    SCE_SYSMODULE_INTERNAL_PAF = 0x80000008,
    SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL = 0x80000024
} SceSysmoduleModuleId;
enum { SCE_SYSMODULE_LOADED = 0, SCE_SYSMODULE_ERROR_UNLOADED = 0x805A1001u };
/* Mirror VitaSDK fields, using native pointers for a host simulation. */
typedef struct SceSysmoduleOpt { int flags; int *result; int unused[2]; } SceSysmoduleOpt;
int sceSysmoduleLoadModule(SceSysmoduleModuleId id);
int sceSysmoduleUnloadModule(SceSysmoduleModuleId id);
int sceSysmoduleIsLoaded(SceSysmoduleModuleId id);
int sceSysmoduleLoadModuleInternal(SceSysmoduleModuleId id);
int sceSysmoduleUnloadModuleInternal(SceSysmoduleModuleId id);
int sceSysmoduleLoadModuleInternalWithArg(SceSysmoduleModuleId id, SceSize args, void *argp, SceSysmoduleOpt *opt);
int sceSysmoduleUnloadModuleInternalWithArg(SceSysmoduleModuleId id, SceSize args, void *argp, SceSysmoduleOpt *opt);
#endif
