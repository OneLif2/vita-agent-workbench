/* Included after the two original launch functions in the isolated comparison. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static const char *failure;
static int platform_rc, sdk_flag, sdk_calls, syncs;
static const char *sdk_uri;
int sceAppMgrLaunchAppByUri(int flags, const char *uri) {
    ++sdk_calls; sdk_flag=flags; sdk_uri=uri;
    printf("dispatch flags=0x%X uri=%s\n",flags,uri);
    return platform_rc;
}
SceUID sceIoOpen(const char *path,int flags,SceMode mode) {
    (void)mode; assert(!strcmp(path,WB_INSTALL_LOG));
    assert(flags==(SCE_O_WRONLY|SCE_O_CREAT|SCE_O_APPEND));
    return !strcmp(failure,"log-error") ? -4 : 11;
}
int sceIoWrite(SceUID fd,const void *src,SceSize n) {
    assert(fd==11); fwrite(src,1,n,stdout); return (int)n;
}
int sceIoSyncByFd(SceUID fd,int zero) { assert(fd==11 && !zero); ++syncs; return 0; }
int sceIoClose(SceUID fd) { assert(fd==11);return 0; }
int sceRtcGetCurrentTick(SceRtcTick *tick) {
    tick->tick=123456; return !strcmp(failure,"rtc-error") ? -3 : 0;
}
int main(int argc,char **argv) {
    assert(argc==3);
    int out=!strcmp(argv[1],"out"); assert(out || !strcmp(argv[1],"back"));
    failure=argv[2]; platform_rc=!strcmp(failure,"launch-error")?-7:0;
    int rc=out?wb_updater_launch():launch_workbench();
    assert(sdk_calls==1 && platform_rc==rc);
    assert(!strcmp(sdk_uri,out?"psgm:play?titleid=INAP00019":"psgm:play?titleid=INAP00018"));
    printf("summary flags=0x%X rc=%d calls=%d syncs=%d\n",sdk_flag,rc,sdk_calls,syncs);
    return 0;
}
