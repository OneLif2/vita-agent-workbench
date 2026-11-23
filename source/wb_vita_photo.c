#include "wb_vita_photo.h"

#include <psp2/photoexport.h>
#include <psp2/sysmodule.h>

int wb_vita_photo_export(const void *verified_data, size_t image_len,
                         int *cleanup_rc) {
    if (cleanup_rc) *cleanup_rc = 0;
    if (!verified_data || !image_len || image_len > WB_VITA_PHOTO_MAX_BYTES)
        return -1;

    const int state = sceSysmoduleIsLoaded(SCE_SYSMODULE_PHOTO_EXPORT);
    const int need_load = state == (int)SCE_SYSMODULE_ERROR_UNLOADED;
    if (state != SCE_SYSMODULE_LOADED && !need_load)
        return state < 0 ? state : -1;
    if (need_load) {
        const int rc = sceSysmoduleLoadModule(SCE_SYSMODULE_PHOTO_EXPORT);
        if (rc < 0) return rc;
    }

    /* FromData accepts an encoded buffer. The zero-version/default metadata
     * and NULL optional buffers are the mGBA Vita FromData usage; the OS
     * chooses its own album location. Never reopen a caller-supplied path. */
    const PhotoExportParam options = {0};
    const int imported = scePhotoExportFromData(verified_data, (SceSize)image_len,
                                                &options, NULL, NULL, NULL,
                                                NULL, 0);
    if (need_load) {
        const int rc = sceSysmoduleUnloadModule(SCE_SYSMODULE_PHOTO_EXPORT);
        if (cleanup_rc) *cleanup_rc = rc;
    }
    return imported;
}
