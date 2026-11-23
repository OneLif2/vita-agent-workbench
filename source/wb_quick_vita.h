#ifndef WB_QUICK_VITA_H
#define WB_QUICK_VITA_H
#include "wb_quick_open.h"
/* A future build cannot inherit the remembered grant. The block bit for
 * programmatic transitions is persisted before calling any launcher. */
/* v1.42: the filename no longer carries WB_BUILD_TAG. The grant itself is
 * still bound to WB_QUICK_OWNER + WB_QUICK_HOST through quick_pair_is_enrolled()
 * on every boot, so a rebuilt or updated app only inherits it when the paired
 * owner key and this device's host key still match. A build tag in the name
 * silently reset the owner's choice on every update. */
#define WB_Q_OPT_NAME "wb-quick-pair.bin"
#define WB_Q_OPT_PATH "savedata0:/" WB_Q_OPT_NAME
enum { Q_OFF=0, Q_DEFAULT=1, Q_REMEMBER=2, Q_FENCE=3, Q_STORE_ERROR=-1 };
static int quick_pref(void){
    int exists=r1_exists(WB_Q_OPT_PATH);uint8_t x=0;
    if(exists==0)return Q_DEFAULT;
    return exists==1 && r1_get(WB_Q_OPT_PATH,&x,1) && x<=Q_FENCE?(int)x:Q_STORE_ERROR;
}
static bool quick_enabled(void){return quick_pref()>Q_OFF;}
static bool quick_write(uint8_t value) {
    SceSize needed=0;uint8_t got=0xff;
    SceAppUtilSaveDataFile f={.filePath=WB_Q_OPT_NAME,.buf=&value,.bufSize=1,.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    return value<=Q_FENCE && sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&needed)==0 &&
           r1_get(WB_Q_OPT_PATH,&got,1) && got==value;
}
static bool quick_switch(bool enabled){return quick_write(enabled?Q_DEFAULT:Q_OFF);}
static bool quick_barrier(void){
    int v=quick_pref();return v==Q_OFF || v==Q_FENCE || (v!=Q_STORE_ERROR && quick_write(Q_FENCE));
}
static bool quick_pair_is_enrolled(void){
    char host[65]={0};return wb_ssh_existing_pin(host) && wb_quick_pair(a.user_pin,host);
}
/* Check BEFORE R1/autoarm consumers clear their markers; missing is not the
 * same as unreadable. Never convert damaged, expired or spent return flows
 * into an unconditional quick-open. */
static bool quick_tomb(const char *path,void *buf,size_t size){
    int exists=r1_exists(path);if(exists==0)return true;
    if(exists!=1 || !r1_get(path,buf,size))return false;
    for(size_t i=0;i<size;i++)if(((uint8_t*)buf)[i])return false;
    return true;
}
static wb_quick_route quick_route(void){
    int v=quick_pref();if(!quick_pair_is_enrolled() || v<=Q_OFF)return WB_Q_NONE;
    r1_local local={0};wb_arm_intent arm={0};
    /* v1.51: a spent arm intent stays in savedata with a non-zero ticket, so
     * quick_tomb() failed forever and every cold start fell back to
     * WB_Q_LOCAL ("PAIRED OPEN NOT CONFIRMED"). Only treat the record as dirty
     * while its marker still exists (i.e. the intent has not been consumed). */
    const bool arm_pending = r1_exists(WB_ARM_MARKER) != 0;
    const bool r1_pending  = r1_exists(WB_R1_INTENT) != 0;
    bool clean=r1_exists(WB_PENDING_PATH)==0 && r1_exists(WBQ_SEAL)==0 && r1_exists(WBQ_TEST)==0 &&
        r1_exists(WB_R1_SUCCESS)==0 && !r1_pending && !arm_pending &&
        (!r1_pending || quick_tomb(R1_LOCAL_PATH,&local,sizeof local)) &&
        (!arm_pending || quick_tomb(WB_ARM_PATH,&arm,sizeof arm));
    char param[1024],data[2048]={0};memset(param,0xa5,sizeof param);
    SceAppUtilAppEventParam event={0};
    int app=sceAppMgrGetAppParam(param);
    SceAppMgrAppState state={0};int sr=_sceAppMgrGetAppState(&state,sizeof state,0x03600011u);
    int ev=clean && app==0 && !param[0] && sr==0 && !state.isSystemUiOverlaid && state.appEventNum?
        sceAppUtilReceiveAppEvent(&event):-1;
    /* 1024 bytes is the entire SDK event payload. The SDK parser receives
     * no buffer size: only pass bounded payloads containing a terminator
     * and a destination larger than the whole fixed input record. */
    int parse=ev==0 && memchr(event.dat,0,sizeof event.dat)?sceAppUtilAppEventParseLiveArea(&event,data):-1;
    const bool no_param = param[0]==0;
    char note[160];snprintf(note,sizeof note,"QUICK ORIGIN clean=%d app=%d empty=%d state=%d count=%u event=%d type=%u livearea=%d p0=%02X",
        clean,app,no_param,sr,(unsigned)state.appEventNum,ev,(unsigned)event.type,parse,(unsigned)(unsigned char)param[0]);(void)log_event(note);
    const wb_quick_route route =
        wb_quick_decide(true,true,clean,v==Q_FENCE,v==Q_REMEMBER,app,no_param,sr,!state.isSystemUiOverlaid,state.appEventNum,ev,parse);
    {
        char ev_note[128];
        snprintf(ev_note,sizeof ev_note,"quick-route clean=%d empty=%d state=%d clear=%d qr=%d",
                 clean,no_param,sr,!state.isSystemUiOverlaid,(int)route);
        char runbuf[24];snprintf(runbuf,sizeof runbuf,"%p",(void*)&route);
        (void)timeline_event(ev_note, "", "");   /* persistent evidence */
        (void)runbuf;
    }
    return route;
}
static bool quick_veto(void){
    SceCtrlData p={0};return sceCtrlPeekBufferPositive(0,&p,1)<=0 || (p.buttons&(SCE_CTRL_START|SCE_CTRL_SELECT))!=0;
}
#endif
