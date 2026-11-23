#ifndef WB_STANDING_MESSAGE_H
#define WB_STANDING_MESSAGE_H
#include "wb_return_policy.h"
#include <stdio.h>
/* A signature is not a local grant: saved standing enrollment and the
 * current sealed queue are always independently verified. */
enum { WB_STANDING_MSG_CAP = 300 };
static inline bool wb_standing_message(char out[WB_STANDING_MSG_CAP],const char *receipt,
         const char *source,const char *run,const char *host_pin,const char *owner_pin) {
    char target[6],host[65],owner[65];
    static const char hx[]="0123456789abcdef";
    if(!wb_r1_receipt(receipt,target) || !wb_r1_version(source) || strcmp(target,source)<=0 ||
       !wb_r1_hex(run,16,true,true) || !wb_r1_hex(host_pin,64,false,true) ||
       !wb_r1_hex(owner_pin,64,false,true))return false;
    for(unsigned i=0;i<64;++i) {
        host[i]=hx[wb_r1_digit(host_pin[i])];owner[i]=hx[wb_r1_digit(owner_pin[i])];
    }
    host[64]=owner[64]=0;
    if(!strcmp(host,owner))return false;
    int n=snprintf(out,WB_STANDING_MSG_CAP,"WB-R1-AUTO-v1\n" WB_TITLE_ID " %sHOST %s\nOWNER %s\nSOURCE %s %s\n",
                   receipt+5,host,owner,source,run);
    return n>0 && n<WB_STANDING_MSG_CAP;
}
static inline bool wb_standing_hex(char const *x,size_t n) {
    return wb_r1_hex(x,n,false,true) && strspn(x,"0123456789abcdef")==n;
}
static inline void wb_standing_decode(const char *x,unsigned char *out,size_t bytes) {
    for(size_t i=0;i<bytes;++i)out[i]=(unsigned char)(wb_r1_digit(x[2*i])*16+wb_r1_digit(x[2*i+1]));
}
static inline bool wb_standing_scalars(const char *r,const char *s) {
    return wb_standing_hex(r,64) && wb_standing_hex(s,64) &&
        strcmp(r,"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")<0 &&
        strcmp(s,"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")<=0;
}
#endif
