#ifndef WB_R1_NOTICE_H
#define WB_R1_NOTICE_H

#include "wb_review_model.h"

/* Presentation state only: no ownership or permission changes, no disk write.
 * A single exact receipt can open the local prompt at most once per queue.
 * Drop it on a changed power generation, focus loss, revoke, or time expiry. */
enum { WB_NOTICE_TTL_MS = 30000 };
typedef struct {
    char receipt[WBQ_CAP];
    uint64_t sent_ms;
    uint32_t power_gen;
    bool pending;
} wb_r1_notice;
static inline bool wb_notice_hex(const char *s) {
    if (!s || strlen(s)!=64 || !wb_r1_hex(s,64,false,true)) return false;
    return strspn(s,"0123456789abcdef")==64;
}
static inline int wb_notice_request(wb_r1_notice *n,bool owner_pty,bool eligible,
                                    int argc,const char *manifest,const char *run,
                                    uint64_t now,uint32_t power,wb_review_reader reader,
                                    wb_out *out,int *status) {
    *status=1;
    if(!owner_pty)return wb_out_puts(out,"ERR r1-notice no-pty\n");
    if(argc!=1 || !wb_notice_hex(manifest))return wb_out_puts(out,"ERR r1-notice usage\n");
    if(!eligible || n->receipt[0])return wb_out_puts(out,"ERR r1-notice busy\n");
    wb_review_model m;
    if(!wb_r1_hex(run,16,true,true) || !wb_review_snapshot(&m,reader))
        return wb_out_puts(out,"ERR r1-notice not-verified\n");
    if(strncmp(m.receipt+11,manifest,64))
        return wb_out_puts(out,"ERR r1-notice mismatch\n");
    const int rc=wb_out_printf(out,
        "OK r1-notice title=" WB_TITLE_ID " target=%s bytes=%u source_run=%s manifest=%.64s\n",
        m.target,(unsigned)m.bytes,run,m.receipt+11);
    if(rc>=0){
        memcpy(n->receipt,m.receipt,sizeof n->receipt);
        n->sent_ms=now;n->power_gen=power;n->pending=true;
        *status=0;
    }
    return rc;
}
static inline void wb_notice_cancel(wb_r1_notice *n){n->pending=false;}
static inline bool wb_notice_ready(wb_r1_notice *n,bool session,bool focus,
                                  uint64_t now,uint32_t power) {
    if(!n->pending)return false;
    if(!focus || power!=n->power_gen || now<n->sent_ms ||
       now-n->sent_ms>=WB_NOTICE_TTL_MS){wb_notice_cancel(n);return false;}
    if(session)return false;
    wb_notice_cancel(n);  /* consume even when the recheck before display fails */
    return true;
}
#endif
