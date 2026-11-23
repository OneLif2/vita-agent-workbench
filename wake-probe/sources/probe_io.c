#include "probe_io.h"
#include <psp2/apputil.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/rtc.h>
#include <string.h>
int wp_read_exact(const char *path,void *out,unsigned len){
    if(!len||len>WP_RESULT_BYTES)return WP_BAD_SIZE;
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);if(fd<0)return fd;
    unsigned done=0;int rc=0;uint8_t extra;
    while(done<len){int n=sceIoRead(fd,(uint8_t*)out+done,len-done);if(n<=0||(unsigned)n>len-done){rc=n<0?n:WP_BAD_SIZE;break;}done+=(unsigned)n;}
    if(!rc){int n=sceIoRead(fd,&extra,1);if(n)rc=n<0?n:WP_BAD_SIZE;}
    int close_rc=sceIoClose(fd);return rc?rc:close_rc;
}
static int sync_path(const char *path){int fd=sceIoOpen(path,SCE_O_RDONLY,0);if(fd<0)return fd;int r=sceIoSyncByFd(fd,0);int c=sceIoClose(fd);return r?r:c;}
int wp_private_put(const char *name,const void *data,unsigned len){
    char path[96];uint8_t verify[WP_RESULT_BYTES];size_t n=strlen(name);
    if(!len||len>sizeof verify||n>64||strchr(name,'/')||strchr(name,':'))return WP_BAD_SIZE;
    memcpy(path,"savedata0:/",11);memcpy(path+11,name,n+1);
    SceAppUtilSaveDataFile f={.filePath=name,.buf=(void*)data,.bufSize=len,.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    SceSize needed=0;int r=sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&needed);if(r)return r;
    r=sync_path(path);if(r)return r;r=wp_read_exact(path,verify,len);return r?r:memcmp(verify,data,len)?WP_VERIFY:0;
}
int wp_load_claim(wp_job*j){return wp_read_exact("savedata0:/" WP_CLAIM_NAME,j,sizeof *j);}
int wp_save_claim(const wp_job*j){return wp_private_put(WP_CLAIM_NAME,j,sizeof *j);}
int wp_load_main(wp_result*r){return wp_read_exact("savedata0:/" WP_MAIN_NAME,r,sizeof *r);}
int wp_save_main(const wp_result*r){return wp_private_put(WP_MAIN_NAME,r,sizeof *r);}
int wp_publish(const wp_result*r){
    int fd=sceIoOpen(WP_RESULT_PATH,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0600);if(fd<0)return fd;
    unsigned done=0;int rc=0;const uint8_t*b=(const uint8_t*)r;
    while(done<sizeof *r){int n=sceIoWrite(fd,b+done,sizeof *r-done);if(n<=0||(unsigned)n>sizeof *r-done){rc=n<0?n:WP_BAD_SIZE;break;}done+=(unsigned)n;}
    if(!rc){rc=sceIoSyncByFd(fd,0);}
    int c=sceIoClose(fd);if(!rc)rc=c;
    wp_result verify;if(!rc)rc=wp_read_exact(WP_RESULT_PATH,&verify,sizeof verify);
    return rc?rc:memcmp(&verify,r,sizeof verify)?WP_VERIFY:0;
}
int wp_clock(uint64_t*now,uint64_t*epoch){SceRtcTick t={0};int rc=sceRtcGetCurrentTick(&t);if(rc)return rc;*now=(uint64_t)sceKernelGetSystemTimeWide();if(!*now||t.tick<=*now)return WP_BAD_CLOCK;*epoch=t.tick-*now;return 0;}
