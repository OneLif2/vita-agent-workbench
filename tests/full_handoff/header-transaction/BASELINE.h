/* Physical-owner return for one staged WBQ2 update; no IPC/SSH path mints this
 * record. Updater can receive the request and publish success, but cannot
 * create the originating title's savedata authorization through Workbench.
 * A privileged native adversary with filesystem access is outside this model. */
#ifndef WB_RETURN_VITA_H
#define WB_RETURN_VITA_H
#include "wb_return_policy.h"
#include "wb_signed_focus.h"
#include <psp2/apputil.h>
#define R1_NAME "wb-r1-owner-v1.bin"
#define R1_LOCAL_PATH "savedata0:/" R1_NAME
enum { R1_ARMED=1, R1_DISPATCHED=2 };
typedef struct { uint64_t phase; wb_r1_ticket t; } r1_local;
static wb_r1_ticket r1_completed;
static bool r1_bound;
static bool r1_source_live;
static uint64_t r1_start_ms,r1_last_rtc;
static bool r1_signed_armed;
/* Only the signed issuer sets this process-local bit and supplies focus
 * endpoints. Neither endpoint nor its bounded interval crosses requests. */
static bool (*r1_signed_begin)(wb_signed_focus *sample);
static bool (*r1_signed_end)(const wb_signed_focus *sample,const char *receipt);
/* 1 present, 0 absent, -1 unknown. Never treat a storage error as consent. */
static int r1_exists(const char *p) {
    SceIoStat st={0};int rc=sceIoGetstat(p,&st);
    return rc>=0?1:((uint32_t)rc==UINT32_C(0x80010002)?0:-1);
}
static int r1_remove(const char *p) {
    int rc=sceIoRemove(p);
    return rc>=0 || (uint32_t)rc==UINT32_C(0x80010002)?WB_OK:WB_E_IO;
}
static uint64_t r1_now(void) {SceRtcTick n;return sceRtcGetCurrentTick(&n)<0?0:n.tick;}
/* A source-run cannot regain its grant by winding the RTC back. All leases
 * are lost on process restart. Reads only latch invalidity in RAM. */
static bool r1_clock(uint64_t now) {
    uint64_t mono=now_ms();
    if(!r1_source_live || now<r1_last_rtc || mono<r1_start_ms ||
       mono-r1_start_ms>=WB_R1_TTL/1000u){r1_source_live=false;return false;}
    r1_last_rtc=now;return true;
}
static bool r1_current(const wb_r1_ticket *t) {
    uint64_t now=r1_now();
    if(!r1_clock(now) || !wb_r1_valid(t,now)){r1_source_live=false;return false;}
    return true;
}
static bool r1_get(const char *p,void *buf,size_t size) {
    size_t n=0;return wq_read(p,buf,size,&n)==WB_OK && n==size;
}
static int r1_save(r1_local *s) {
    SceSize needed=0;r1_local got={0};
    SceAppUtilSaveDataFile f={.filePath=R1_NAME,.buf=s,.bufSize=sizeof *s,.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    return sceAppUtilSaveDataDataSave(NULL,&f,1,NULL,&needed)==0 && r1_get(R1_LOCAL_PATH,&got,sizeof got)
       && !memcmp(&got,s,sizeof got)?WB_OK:WB_E_IO;
}
static int r1_spend(void *unused) {
    (void)unused;r1_local zero={0};return r1_save(&zero);
}
static int r1_revoke(void) {
    r1_source_live=false;
    r1_signed_armed=false;
    r1_signed_begin=NULL;
    r1_signed_end=NULL;
    int present=r1_exists(R1_LOCAL_PATH);int x=present<0?WB_E_IO:WB_OK;
    if(present>0) {
        r1_local s={0};
        if(!r1_get(R1_LOCAL_PATH,&s,sizeof s) || s.phase!=0)x=r1_spend(NULL);
    }
    int y=r1_remove(WB_R1_INTENT), z=r1_remove(WB_R1_SUCCESS);
    return x==WB_OK && y==WB_OK && z==WB_OK?WB_OK:WB_E_IO;
}
static bool r1_queue(char receipt[WBQ_CAP]) {
    char after[WBQ_CAP]={0};
    return wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,receipt)==WB_OK && queued_core_check()==WB_OK &&
           wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,after)==WB_OK && !strcmp(after,receipt);
}
/* Only invoked via the physical wrapper or after verified signed consent
 * has durably spent this target, not directly via a terminal descriptor. */
static int r1_issue_ticket(const char *reviewed,bool (*ready)(const wb_signed_focus *),
                           const wb_signed_focus *sample) {
    r1_local s={0};char receipt[WBQ_CAP],nonce[33];uint8_t rnd[16];
    if(!r1_queue(receipt) || strcmp(receipt,reviewed) || (ready && !ready(sample)) ||
       r1_revoke()!=WB_OK)return WB_E_STATE;
    if(sceKernelGetRandomNumber(rnd,sizeof rnd)<0)return WB_E_IO;
    hex(nonce,rnd,sizeof rnd);
    if(!wb_r1_make(&s.t,r1_now(),WB_VERSION,a.run_hex,nonce,a.user_pin,a.pin,receipt))return WB_E_STATE;
    s.phase=R1_ARMED;int rc=r1_save(&s);
    if(rc==WB_OK){r1_start_ms=now_ms();r1_last_rtc=s.t.issued;r1_source_live=true;}
    return rc;
}
static int r1_issue_local(const char *reviewed) {return r1_issue_ticket(reviewed,NULL,NULL);}
static bool r1_authorized(const r1_local *s,const char *nonce,const char *receipt) {
    return s->phase==R1_ARMED && r1_current(&s->t) && !strcmp(s->t.source_ver,WB_VERSION)
       && !strcmp(s->t.source_run,a.run_hex) && !strcmp(s->t.nonce,nonce) && !strcmp(s->t.receipt,receipt)
       && wb_r1_pin_equal(s->t.owner_pin,a.user_pin) && wb_r1_pin_equal(s->t.host_pin,a.pin);
}
static int r1_apply(const char *nonce,bool dispatch) {
    r1_local s;char receipt[WBQ_CAP];
    wb_signed_focus sample={0};
    const bool signed_ticket=r1_signed_armed;
    if(!r1_get(R1_LOCAL_PATH,&s,sizeof s))return WB_E_STATE;
    if(signed_ticket && (!r1_signed_begin || !r1_signed_end || !r1_signed_begin(&sample)))return WB_E_STATE;
    if(!r1_queue(receipt) || !r1_authorized(&s,nonce,receipt))return WB_E_STATE;
    if(signed_ticket && (!r1_signed_armed || !r1_signed_end(&sample,receipt)))return WB_E_STATE;
    if(!dispatch)return WB_OK;
    s.phase=R1_DISPATCHED;
    wb_r1_ticket got={0};
    if(r1_remove(WB_R1_SUCCESS)!=WB_OK || r1_remove(WB_R1_INTENT)!=WB_OK ||
       r1_save(&s)!=WB_OK || wq_save(WB_R1_INTENT,&s.t,sizeof s.t)!=WB_OK ||
       !r1_get(WB_R1_INTENT,&got,sizeof got) || memcmp(&got,&s.t,sizeof got)){
        (void)r1_revoke();return WB_E_IO;
    }
    return WB_OK;
}
static bool r1_boot(wb_r1_ticket *accepted) {
    r1_local s={0};wb_r1_ticket proof={0};char installed[WBQ_CAP]={0},hp[65]={0};
    int present=r1_exists(R1_LOCAL_PATH);
    if(present<=0) {
        (void)r1_remove(WB_R1_SUCCESS);(void)r1_remove(WB_R1_INTENT);
        return false;
    }
    bool readable=r1_get(R1_LOCAL_PATH,&s,sizeof s);
    if(readable && s.phase==0){(void)r1_remove(WB_R1_SUCCESS);(void)r1_remove(WB_R1_INTENT);return false;}
    bool match=readable && s.phase==R1_DISPATCHED && wb_r1_valid(&s.t,r1_now())
        && r1_get(WB_R1_SUCCESS,&proof,sizeof proof) && wb_ssh_existing_pin(hp)
        && wq_installed_receipt("ux0:app/" WB_TITLE_ID,WB_VERSION,installed)==WB_OK
        && wb_r1_return(&s.t,&proof,r1_now(),WB_VERSION,a.run_hex,a.user_pin,hp,installed);
    /* A wrong proof/restart/cancel, or failure to persist the spend, never
     * yields an unattended return. No SSH key is generated in this path. */
    bool consumed=wb_r1_consume(match,r1_spend,NULL);
    int x=r1_remove(WB_R1_SUCCESS), y=r1_remove(WB_R1_INTENT);
    if(!consumed || x || y)return false;
    *accepted=s.t;return true;
}
static int r1_status(wb_out *out) {
    const char *state="none";r1_local s={0};wb_r1_ticket *t=NULL;
    if(r1_bound){state="returned";t=&r1_completed;}
    else if(r1_get(R1_LOCAL_PATH,&s,sizeof s) && (s.phase==R1_ARMED || s.phase==R1_DISPATCHED)){
        if(!r1_current(&s.t))state="expired";
        else{
            char live[WBQ_CAP]={0};
            bool same=wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,live)==WB_OK && !strcmp(live,s.t.receipt);
            if(same && !strcmp(s.t.source_run,a.run_hex) && !strcmp(s.t.source_ver,WB_VERSION) &&
               wb_r1_pin_equal(s.t.owner_pin,a.user_pin) && wb_r1_pin_equal(s.t.host_pin,a.pin)){
                state=s.phase==R1_ARMED?"authorized":"dispatched";t=&s.t;
            }
        }
    }
    return wb_out_printf(out,"r1 state=%s source_run=%s nonce=%s target=%s run=%s manifest=%.*s\n",state,
        t?t->source_run:"-",t?t->nonce:"-",t?t->target_ver:"-",a.run_hex,t?64:1,t?t->receipt+11:"-");
}
#endif
