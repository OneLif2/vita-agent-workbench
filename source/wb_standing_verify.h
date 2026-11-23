#ifndef WB_STANDING_VERIFY_H
#define WB_STANDING_VERIFY_H
#include "wb_standing_message.h"
#include "wb_standing_provision.h"
#include "wb_sha256.h"
#include <mbedtls/ecdsa.h>
static inline const char *wb_standing_key_id(void) { return WB_STANDING_SIGNER; }
static inline bool wb_standing_provisioned(const char *host_pin,const char *owner_pin) {
    char h[65],o[65];
    return wb_r1_normal_pin(h,host_pin) && wb_r1_normal_pin(o,owner_pin) &&
           wb_r1_pin_equal(h,WB_STANDING_HOST) && wb_r1_pin_equal(o,WB_STANDING_OWNER);
}
static inline bool wb_standing_verify(const char *receipt,const char *source,const char *run,
            const char *host_pin,const char *owner_pin,const char *rs,const char *ss) {
    char msg[WB_STANDING_MSG_CAP],key_id[65];
    if(!wb_standing_provisioned(host_pin,owner_pin) ||
       !wb_standing_message(msg,receipt,source,run,host_pin,owner_pin) ||
       !wb_standing_scalars(rs,ss) || !wb_standing_hex(WB_STANDING_SEC1,130))return false;
    unsigned char sec[65],r[32],s[32],hash[32];wb_sha256 sh;
    wb_standing_decode(WB_STANDING_SEC1,sec,sizeof sec);if(sec[0]!=4)return false;
    wb_sha256_init(&sh);wb_sha256_update(&sh,sec,sizeof sec);wb_sha256_final(&sh,hash);
    wb_sha_hex(hash,sizeof hash,key_id);
    if(strcmp(key_id,wb_standing_key_id()))return false;
    wb_standing_decode(rs,r,sizeof r);wb_standing_decode(ss,s,sizeof s);
    wb_sha256_init(&sh);wb_sha256_update(&sh,msg,strlen(msg));wb_sha256_final(&sh,hash);
    mbedtls_ecp_group group;mbedtls_ecp_point pt;mbedtls_mpi mr,ms;
    mbedtls_ecp_group_init(&group);mbedtls_ecp_point_init(&pt);mbedtls_mpi_init(&mr);mbedtls_mpi_init(&ms);
    bool ok=mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)==0 &&
            mbedtls_ecp_point_read_binary(&group,&pt,sec,sizeof sec)==0 &&
            mbedtls_ecp_check_pubkey(&group,&pt)==0 &&
            mbedtls_mpi_read_binary(&mr,r,sizeof r)==0 && mbedtls_mpi_read_binary(&ms,s,sizeof s)==0 &&
            mbedtls_ecdsa_verify(&group,hash,sizeof hash,&pt,&mr,&ms)==0;
    mbedtls_mpi_free(&ms);mbedtls_mpi_free(&mr);mbedtls_ecp_point_free(&pt);mbedtls_ecp_group_free(&group);
    return ok;
}
#endif
