#ifndef WB_RETURN_POLICY_H
#define WB_RETURN_POLICY_H
/* R1: opt-in return after ONE verified update. This is not authentication:
 * current host/owner identity, physical owner gesture, source of the saved
 * ticket, verified updater success, and durable consume are checked by the
 * respective callers. No SSH command or TestApp marker mints a ticket. */
#include "wb_queued.h"
#include <stddef.h>

#define WB_R1_INTENT  WBQ_STORE "/r1-intent.bin"
#define WB_R1_SUCCESS WBQ_STORE "/r1-success.bin"
#define WB_R1_TTL UINT64_C(28800000000) /* RTC ticks: 8h, expiry exclusive */

/* Same Vita ABI for producer/updater/consumer. Fixed length protects against
 * truncated or trailing records. No pointers, time_t, bool or padding bytes. */
typedef struct wb_r1_ticket {
    uint64_t issued, expires;
    char magic[8], title[10], source_ver[6], target_ver[6], source_run[17],
         nonce[33], owner_pin[65], host_pin[65], receipt[WBQ_CAP];
    unsigned char reserved[3];
} wb_r1_ticket;
_Static_assert(WBQ_CAP==99 && offsetof(wb_r1_ticket,magic)==16 &&
               offsetof(wb_r1_ticket,receipt)==226 && sizeof(wb_r1_ticket)==328,
               "R1 fixed record format");

static inline bool wb_r1_version(const char *v) {
    if (!v) return false;
    for (size_t i=0; i<5; ++i)
        if (i==2 ? v[i]!='.' : (v[i]<'0' || v[i]>'9')) return false;
    return v[5]==0;
}
static inline unsigned wb_r1_digit(char c) {
    if (c>='0' && c<='9') return (unsigned)(c-'0');
    if (c>='A' && c<='F') return (unsigned)(c-'A'+10);
    if (c>='a' && c<='f') return (unsigned)(c-'a'+10);
    return 16;
}
static inline bool wb_r1_hex(const char *s, size_t n, bool upper, bool nonzero) {
    if (!s) return false;
    unsigned used=0;
    for(size_t i=0; i<n; ++i) {
        unsigned d=wb_r1_digit(s[i]);
        if (d>15 || (upper && s[i]>='a' && s[i]<='f')) return false;
        used|=d;
    }
    return s[n]==0 && (!nonzero || used);
}
static inline bool wb_r1_pin_equal(const char *a,const char *b) {
    if (!wb_r1_hex(a,64,true,true) || !wb_r1_hex(b,64,false,true))return false;
    unsigned diff=0;
    for(unsigned i=0; i<64; ++i)diff|=wb_r1_digit(a[i])^wb_r1_digit(b[i]);
    return diff==0;
}
static inline bool wb_r1_normal_pin(char *dst,const char *src) {
    static const char chars[]="0123456789ABCDEF";
    if (!wb_r1_hex(src,64,false,true)) return false;
    for(unsigned i=0;i<64;++i) dst[i]=chars[wb_r1_digit(src[i])];
    dst[64]=0;return true;
}
/* Source must be a NUL-terminated string (or a validated ticket field).
 * Wire receipt is exactly "WBQ2 NN.NN <64 lowercase hex> <bytes>\n". */
static inline bool wb_r1_receipt(const char *s,char ver[6]) {
    if(!s || strncmp(s,"WBQ2 ",5)) return false;
    const char *p=s+5;char v[6]={0};
    for(unsigned i=0;i<5;++i){if(!*p)return false;v[i]=*p++;}
    if(!wb_r1_version(v) || *p++!=' ')return false;
    for(unsigned i=0;i<64;++i) {
        char c=*p++;if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    }
    if(*p++!=' ' || *p<'1' || *p>'9')return false;
    uint32_t bytes=0;
    while(*p>='0'&&*p<='9') {
        unsigned d=(unsigned)(*p++ - '0');
        if(bytes>(4u*WBQ_FILE_MAX-d)/10u)return false;
        bytes=bytes*10u+d;
    }
    if(bytes<4 || *p++!='\n' || *p!=0) return false;
    if(ver)memcpy(ver,v,6);
    return true;
}
static inline bool wb_r1_valid(const wb_r1_ticket *t,uint64_t now) {
    if(!t || !t->issued || now<t->issued || t->expires<=t->issued ||
       t->expires-t->issued!=WB_R1_TTL || now>=t->expires) return false;
    if(memcmp(t->magic,"WBR1-01",8) || memcmp(t->title,WB_TITLE_ID,10) ||
       !wb_r1_version(t->source_ver) || !wb_r1_version(t->target_ver) ||
       memcmp(t->source_ver,t->target_ver,5)>=0 ||
       !wb_r1_hex(t->source_run,16,true,true)||!wb_r1_hex(t->nonce,32,true,true)||
       !wb_r1_hex(t->owner_pin,64,true,true)||!wb_r1_hex(t->host_pin,64,true,true))
        return false;
    if(t->reserved[0]||t->reserved[1]||t->reserved[2]) return false;
    const char *nul=(const char*)memchr(t->receipt,0,sizeof t->receipt);
    if(!nul)return false;
    for(const char *p=nul+1;p<t->receipt+sizeof t->receipt;++p) if(*p)return false;
    char ver[6];
    return wb_r1_receipt(t->receipt,ver) && memcmp(ver,t->target_ver,6)==0;
}
static inline bool wb_r1_make(wb_r1_ticket *t,uint64_t now,const char *source_ver,
        const char *source_run,const char *nonce,const char *owner_pin,
        const char *host_pin,const char *receipt) {
    if(!t)return false;
    memset(t,0,sizeof *t);
    wb_r1_ticket v={0};
    if(!now || now>UINT64_MAX-WB_R1_TTL ||
       !wb_r1_version(source_ver) || !wb_r1_hex(source_run,16,true,true) ||
       !wb_r1_hex(nonce,32,true,true) || !wb_r1_normal_pin(v.owner_pin,owner_pin) ||
       !wb_r1_normal_pin(v.host_pin,host_pin) || !wb_r1_receipt(receipt,v.target_ver))
        return false;
    size_t n=strlen(receipt);
    if(n>=sizeof v.receipt)return false;
    v.issued=now;v.expires=now+WB_R1_TTL;
    memcpy(v.magic,"WBR1-01",8);memcpy(v.title,WB_TITLE_ID,10);
    memcpy(v.source_ver,source_ver,6);memcpy(v.source_run,source_run,17);
    memcpy(v.nonce,nonce,33);memcpy(v.receipt,receipt,n+1);
    if(!wb_r1_valid(&v,now))return false;
    *t=v;return true;
}
static inline bool wb_r1_handoff(const wb_r1_ticket *t,uint64_t now,
        const char *current_installed_ver,const char *verified_receipt) {
    return wb_r1_valid(t,now) && wb_r1_version(current_installed_ver) &&
           !memcmp(t->source_ver,current_installed_ver,6) &&
           wb_r1_receipt(verified_receipt,NULL) && !strcmp(t->receipt,verified_receipt);
}
static inline bool wb_r1_return(const wb_r1_ticket *priv,const wb_r1_ticket *success,
        uint64_t now,const char *running_ver,const char *new_run,const char *owner_pin,
        const char *host_pin,const char *installed_receipt) {
    return wb_r1_valid(priv,now) && success && !memcmp(priv,success,sizeof *priv) &&
           wb_r1_version(running_ver) && !memcmp(priv->target_ver,running_ver,6) &&
           wb_r1_hex(new_run,16,true,true) && memcmp(priv->source_run,new_run,16)!=0 &&
           wb_r1_pin_equal(priv->owner_pin,owner_pin) && wb_r1_pin_equal(priv->host_pin,host_pin) &&
           wb_r1_receipt(installed_receipt,NULL) && !strcmp(priv->receipt,installed_receipt);
}
/* Callback must invalidate AND read-back verify the private record. A public
 * proof cannot re-arm after consumption; write/verify failure is never grant. */
static inline bool wb_r1_consume(bool matches,int (*invalidate)(void *),void *ctx) {
    if(!invalidate)return false;
    int rc=invalidate(ctx);
    return matches && rc==0;
}
#endif
