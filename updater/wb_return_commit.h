#ifndef WB_RETURN_COMMIT_H
#define WB_RETURN_COMMIT_H
/* No networking or permission creation: the updater can only echo the exact
 * local consent for this successful WBQ2 handoff. The newly installed core
 * independently checks its private owner-approved intent and consumes it. */
#include "../source/wbq_io.h"
#include "../source/wb_return_policy.h"
#define WB_R1_DRAFT WB_R1_SUCCESS ".tmp"
static inline int wru_drop(const char *p) {
    int rc=sceIoRemove(p);
    return (rc>=0 || (uint32_t)rc==UINT32_C(0x80010002)) ? WB_OK : WB_E_IO;
}
/* Destructively take the exported ticket exactly once. A stale/corrupt
 * ticket must never block an ordinary, manually armed, verified upgrade. */
static inline bool wru_take(wb_r1_ticket *t) {
    size_t n=0;
    bool cleared=wru_drop(WB_R1_SUCCESS)==WB_OK;
    if(wru_drop(WB_R1_DRAFT)!=WB_OK)cleared=false;
    int rc=wq_read(WB_R1_INTENT,t,sizeof *t,&n);
    bool taken=sceIoRemove(WB_R1_INTENT)>=0;
    if(!cleared || rc || n!=sizeof *t || !taken){
        memset(t,0,sizeof *t);
        return false;
    }
    return true;
}
static inline int wru_complete(const wb_r1_ticket *t,uint64_t now,
                               const char *source,const char *receipt,int promote_rc) {
    if(promote_rc!=0 || !receipt || !receipt[0] ||
       !wb_r1_handoff(t,now,source,receipt))return WB_E_STATE;
    wb_r1_ticket copy;size_t n=0;
    int rc=wq_save(WB_R1_DRAFT,t,sizeof *t); /* write all, sync fd, close */
    if(rc==WB_OK)rc=wq_read(WB_R1_DRAFT,&copy,sizeof copy,&n);
    if(rc==WB_OK && (n!=sizeof copy || memcmp(&copy,t,n)))rc=WB_E_IO;
    if(rc==WB_OK && sceIoRename(WB_R1_DRAFT,WB_R1_SUCCESS)<0)rc=WB_E_IO;
    if(rc!=WB_OK)(void)wru_drop(WB_R1_DRAFT);
    return rc;
}
#endif
