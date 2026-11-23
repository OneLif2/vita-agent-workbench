#ifndef INA_AUTH_MODES_H
#define INA_AUTH_MODES_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/platform_util.h>
enum {MODE_PIN_BYTES=32, MODE_CODE_CHARS=16, MODE_TOTAL_ATTEMPTS=3, MODE_WAIT_MS=2000};
typedef enum { MODE_NONE=0, MODE_A_PASSWORD, MODE_B_KEY, MODE_C_INTERACTIVE } Mode;
typedef struct {
    Mode mode;
    uint64_t until, earliest, challenge_peer;
    unsigned attempts;
    bool challenge;
    bool accepted;
    uint8_t pin[MODE_PIN_BYTES];
    uint8_t code[MODE_CODE_CHARS];
} AuthMode;
static inline bool auth_nonzero(const uint8_t *s,size_t n){
    unsigned b=0;for(size_t i=0;i<n;i++)b|=s[i];return !!b;
}
/* 16 case-sensitive Base32 characters, 80 bits from a 10-byte secure RNG draw. */
static inline void auth_encode_code(uint8_t out[MODE_CODE_CHARS],const uint8_t in[10]){
    const char a[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for(unsigned i=0;i<2;i++) {
        uint64_t v=0;for(unsigned j=0;j<5;j++)v=(v<<8)|in[5*i+j];
        for(unsigned j=0;j<8;j++)out[8*i+j]=(uint8_t)a[(v>>(35-5*j))&31u];
    }
}
static inline bool auth_live(const AuthMode *a,Mode m,uint64_t t){
    return a->mode==m&&m!=MODE_NONE&&t<a->until&&!a->accepted;
}
static inline bool auth_attempt(AuthMode *a,Mode m,uint64_t t){
    if(!auth_live(a,m,t)||t<a->earliest||a->attempts>=MODE_TOTAL_ATTEMPTS||
       t>UINT64_MAX-MODE_WAIT_MS)return false;
    a->attempts++;
    a->earliest=t+MODE_WAIT_MS;
    return true;
}
static inline bool auth_key_probe(const AuthMode *a,const uint8_t pin[MODE_PIN_BYTES],uint64_t t){
    return auth_live(a,MODE_B_KEY,t)&&a->attempts<MODE_TOTAL_ATTEMPTS&&t>=a->earliest&&
           auth_nonzero(a->pin,sizeof a->pin)&&mbedtls_ct_memcmp(a->pin,pin,MODE_PIN_BYTES)==0;
}
static inline bool auth_key_commit(AuthMode *a,const uint8_t pin[MODE_PIN_BYTES],
                                   bool valid_signature,uint64_t t){
    if(!auth_attempt(a,MODE_B_KEY,t))return false;
    if(!valid_signature||!auth_nonzero(a->pin,sizeof a->pin)||
       mbedtls_ct_memcmp(a->pin,pin,MODE_PIN_BYTES)!=0)return false;
    return a->accepted=true;
}
static inline bool auth_issue_challenge(AuthMode *a,uint64_t peer,uint64_t t){
    if(!peer||!auth_live(a,MODE_C_INTERACTIVE,t)||a->challenge||
       !auth_nonzero(a->code,sizeof a->code)||t<a->earliest||a->attempts>=MODE_TOTAL_ATTEMPTS)return false;
    a->challenge_peer=peer;return a->challenge=true;
}
/* Consume code on one response regardless of success, before enabling status. */
static inline bool auth_reply_code(AuthMode *a,const uint8_t *s,size_t n,uint64_t peer,uint64_t t){
    if(a->mode!=MODE_C_INTERACTIVE||!a->challenge)return false;
    const bool same_peer=peer&&peer==a->challenge_peer;
    a->challenge=false;a->challenge_peer=0;
    const bool ok=same_peer&&auth_attempt(a,MODE_C_INTERACTIVE,t)&&s&&n==sizeof a->code&&
        auth_nonzero(a->code,sizeof a->code)&&mbedtls_ct_memcmp(a->code,s,n)==0;
    mbedtls_platform_zeroize(a->code,sizeof a->code);
    if(ok)a->accepted=true;
    return ok;
}
static inline void auth_drop_peer(AuthMode *a,uint64_t peer){
    if(a->mode==MODE_C_INTERACTIVE&&a->challenge&&a->challenge_peer==peer){
        a->challenge=false;a->challenge_peer=0;
        mbedtls_platform_zeroize(a->code,sizeof a->code);
    }
}
static inline void auth_end(AuthMode *a){mbedtls_platform_zeroize(a,sizeof *a);}
#endif
