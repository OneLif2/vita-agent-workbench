#ifndef WB_REVIEW_MODEL_H
#define WB_REVIEW_MODEL_H
/* Physical review and read-only observation consume the exact same render
 * model. It is not a framebuffer read, a reservation, or an authorization. */
#include "wb_return_policy.h"
#include "wb_out.h"
typedef struct {
    char receipt[WBQ_CAP],target[6],label[50],groups[72];
    uint32_t bytes;
} wb_review_model;
typedef bool (*wb_review_reader)(char receipt[WBQ_CAP]);
static inline bool wb_review_snapshot(wb_review_model *m,wb_review_reader reader) {
    if(!m || !reader)return false;
    memset(m,0,sizeof *m);
    if(!reader(m->receipt) || !memchr(m->receipt,0,sizeof m->receipt) ||
       !wb_r1_receipt(m->receipt,m->target))return false;
    (void)snprintf(m->label,sizeof m->label,"R1 UPDATE %.5s / " WB_TITLE_ID,m->target);
    unsigned pos=0;
    for(unsigned i=0;i<64;++i){
        if(i&&i%8==0)m->groups[pos++]=' ';
        char c=m->receipt[11+i];m->groups[pos++]=(c>='a'&&c<='f')?(char)(c-'a'+'A'):c;
    }
    m->groups[pos]=0;
    /* Validated by wb_r1_receipt: positive, <=4*WBQ_FILE_MAX, LF terminator. */
    for(const char *p=m->receipt+76;*p!='\n';++p)m->bytes=m->bytes*10u+(unsigned)(*p-'0');
    return true;
}
static inline int wb_review_describe(bool owner_pty,int argc,const char *run,
                                     wb_review_reader reader,wb_out *out,int *status) {
    *status=1;
    if(!owner_pty)return wb_out_puts(out,"ERR r1-review no-pty\n");
    if(argc)return wb_out_puts(out,"ERR r1-review usage\n");
    wb_review_model m;
    if(!wb_r1_hex(run,16,true,true)||!wb_review_snapshot(&m,reader))
        return wb_out_puts(out,"ERR r1-review not-verified\n");
    int rc=wb_out_printf(out,"OK r1-review model=local-review title=" WB_TITLE_ID " target=%s bytes=%u source_run=%s\ngroups=%s\n",
                         m.target,(unsigned)m.bytes,run,m.groups);
    if(rc>=0)*status=0;
    return rc;
}
#endif
