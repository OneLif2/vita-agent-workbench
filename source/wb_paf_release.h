#ifndef WB_PAF_RELEASE_H
#define WB_PAF_RELEASE_H

#include <stddef.h>
#include <psp2/sysmodule.h>

/* The fourth argument is an option record, not a pointer to a single
 * status word. The VitaSDK ABI defines SceSysmoduleOpt as 16 bytes on ARM32;
 * leave all flags and reserved fields zero. The result slot is writable
 * for the entire synchronous call. Do not mask a failed release. */
static int unload_paf(void) {
    int result = 0;
    SceSysmoduleOpt opt = { .result = &result };
    const int rc = sceSysmoduleUnloadModuleInternalWithArg(
        SCE_SYSMODULE_INTERNAL_PAF, 0, NULL, &opt);
    return rc < 0 ? rc : result < 0 ? result : rc;
}

#endif
