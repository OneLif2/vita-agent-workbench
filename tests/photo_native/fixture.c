#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <psp2/sysmodule.h>
#include <psp2/photoexport.h>
#include "wb_vita_photo.h"

static int state, load_rc, import_rc, unload_rc;
static char calls[8];
static const unsigned char data[] = {0xff, 0xd8, 0xff, 0xd9};

static void step(char c, SceSysmoduleModuleId m) {
    assert(m == SCE_SYSMODULE_PHOTO_EXPORT);
    size_t n = strlen(calls);
    assert(n + 1 < sizeof calls);
    calls[n] = c;
    calls[n + 1] = 0;
}
int sceSysmoduleIsLoaded(SceSysmoduleModuleId m) { step('Q',m); return state; }
int sceSysmoduleLoadModule(SceSysmoduleModuleId m) { step('L',m); return load_rc; }
int sceSysmoduleUnloadModule(SceSysmoduleModuleId m) { step('U',m); return unload_rc; }
int scePhotoExportFromData(const void *b, SceSize n, const PhotoExportParam *p,
                           void *work, void *cb, void *user, char *path, SceSize cap) {
    assert(b == data && n == sizeof data);
    assert(p && !p->version && !p->photoTitle && !p->gameTitle && !p->gameComment);
    for (size_t i=0; i<8; ++i) assert(p->reserved[i] == 0);
    assert(!work && !cb && !user && !path && !cap);
    step('I',SCE_SYSMODULE_PHOTO_EXPORT);
    return import_rc;
}
static void check(const char *name, int st, int load, int imp, int unload,
                  int result, int cleanup, const char *sequence) {
    state = st; load_rc = load; import_rc = imp; unload_rc = unload; calls[0] = 0;
    int detail = 172;
    int rc = wb_vita_photo_export(data,sizeof data,&detail);
    assert(rc == result && detail == cleanup && strcmp(sequence,calls) == 0);
    printf("PASS %s rc=%d cleanup=%d calls=%s\n",name,rc,detail,calls);
}
int main(void) {
    const int unloaded = (int)SCE_SYSMODULE_ERROR_UNLOADED;
    int cleanup = 91;
    assert(wb_vita_photo_export(NULL,1,&cleanup) < 0 && cleanup == 0);
    assert(wb_vita_photo_export(data,0,NULL) < 0);
    assert(wb_vita_photo_export(data,(size_t)WB_VITA_PHOTO_MAX_BYTES+1,&cleanup) < 0);
    assert(calls[0] == 0);
    puts("PASS null/empty/oversized inputs never touch modules or Photos");
    check("system already loaded",0,0,0,0,0,0,"QI");
    check("own load import release",unloaded,0,0,0,0,0,"QLIU");
    check("load failed",unloaded,-2,0,0,-2,0,"QL");
    check("query failed",-3,0,0,0,-3,0,"Q");
    check("unrecognized positive query",4,0,0,0,-1,0,"Q");
    check("import refused when borrowed",0,0,-4,0,-4,0,"QI");
    check("import refused when owned",unloaded,0,-4,0,-4,0,"QLIU");
    check("successful import despite failed cleanup",unloaded,0,0,-5,0,-5,"QLIU");
    check("dual failure keeps both codes",unloaded,0,-4,-5,-4,-5,"QLIU");
    return 0;
}
