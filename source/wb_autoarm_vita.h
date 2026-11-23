#ifndef WB_AUTOARM_VITA_H
#define WB_AUTOARM_VITA_H
#include "wb_autoarm.h"
#include <psp2/apputil.h>
#define WB_ARM_NAME "wb-arm-request-v2.bin"
#define WB_ARM_PATH "savedata0:/" WB_ARM_NAME
#define WB_ARM_MARKER WB_ROOT "/autoarm.txt"
/* Use AppUtil for save writes, as for the enrolled host identity. A fixed-size
 * zero record is a tombstone, not an empty request. Verify the persisted bytes. */
static int wb_arm_save(wb_arm_intent *in) {
    SceSize required=0;
    SceAppUtilSaveDataFile f={.filePath=WB_ARM_NAME,.buf=in,.bufSize=sizeof *in,.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    uint8_t observed[sizeof *in+1];size_t n=0;
    if(sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&required)!=0 ||
       wb_vita_read_small(WB_ARM_PATH,observed,sizeof observed,&n)!=WB_OK ||
       n!=sizeof *in || memcmp(in,observed,n)) return WB_E_IO;
    return WB_OK;
}
static int wb_arm_cancel(void) { wb_arm_intent zero={0};return wb_arm_save(&zero); }
static int wb_arm_issue(const char *job,const char *cse) {
    wb_arm_intent i={0}; SceRtcTick now;uint8_t rnd[8],nz=0;char body[160],marker[144];
    if(strlen(job)>=sizeof i.job || strlen(cse)>=sizeof i.cse || sceRtcGetCurrentTick(&now)<0 ||
       !now.tick || sceKernelGetRandomNumber(rnd,sizeof rnd)<0) return WB_E_STATE;
    for(size_t k=0;k<sizeof rnd;k++) nz|=rnd[k];
    if(!nz)return WB_E_STATE;
    i.issued=now.tick;strcpy(i.job,job);strcpy(i.cse,cse);hex(i.ticket,rnd,sizeof rnd);
    if(!wb_arm_text(&i,body,marker))return WB_E_ARG;
    int rc=sceIoRemove(WB_ARM_MARKER);
    if(rc<0 && (uint32_t)rc!=UINT32_C(0x80010002)) return WB_E_IO;
    if(wb_arm_cancel()!=WB_OK || wb_vita_write_file(WB_JOB_PATH,body,strlen(body),false)!=WB_OK ||
       wb_arm_save(&i)!=WB_OK) return WB_E_IO;
    return WB_OK;
}
static bool wb_arm_consume(char accepted_job[64]) {
    uint8_t bytes[sizeof(wb_arm_intent)+1];wb_arm_intent i={0};
    char j[161],m[145];size_t in=0,jn=0,mn=0;SceRtcTick now;
    bool exists=wb_vita_read_small(WB_ARM_PATH,bytes,sizeof bytes,&in)==WB_OK;
    if(exists && in==sizeof i)memcpy(&i,bytes,in);
    bool matched=exists && sceRtcGetCurrentTick(&now)>=0 &&
        wb_vita_read_small(WB_JOB_PATH,j,sizeof j,&jn)==WB_OK &&
        wb_vita_read_small(WB_ARM_MARKER,m,sizeof m,&mn)==WB_OK &&
        wb_arm_match(&i,now.tick,j,jn,m,mn);
    /* Invalidate first, even for malformed, stale, or interrupted launches.
     * A public marker alone, or a failed consume, never arms the listener. */
    bool spent=exists && wb_arm_cancel()==WB_OK;
    int removed=sceIoRemove(WB_ARM_MARKER);
    if(!matched || !spent || removed<0)return false;
    strcpy(accepted_job,i.job);return true;
}
#endif
