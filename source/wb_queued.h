#ifndef WB_QUEUED_H
#define WB_QUEUED_H
#include "wb_err.h"
#include "wb_sfo.h"
#include "wb_ver.h"
#include "wb_sha256.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define WBQ_PREFIX "WBQ2 "
#define WBQ_CAP 99
#define WBQ_VERLEN 5
#define WBQ_INPUT_MAX (4u*1024u*1024u)
#define WBQ_FILE_MAX (8u*1024u*1024u)
#define WBQ_STORE "ux0:data/INAP00019"
#define WBQ_SEAL WBQ_STORE "/sealed-core.txt"
#define WBQ_TEST WBQ_STORE "/selfcheck.txt"
#define WBQ_FINAL WBQ_STORE "/sealed-stage"
#define WBQ_INSTALLED "ux0:app/" WB_TITLE_ID "/sce_sys/param.sfo"
/* Hash domain, fixed order, exact names, 64-bit big-endian size and 32 raw hash bytes.
 * No delimiter ambiguity; head.bin generated from authenticated SFO is also bound. */
static const char *const wbq_names[4]={"eboot.bin","sce_sys/param.sfo","sce_sys/package/head.bin","workbench_payload.suprx"};
typedef struct {uint64_t size[4];uint8_t hash[4][32];} wbq_manifest;
static inline bool wbq_version_ok(const char *v){
 if(!v || strlen(v)!=5)return false;
 for(unsigned i=0;i<5;i++)if(i==2 ? v[i]!='.' : v[i]<'0'||v[i]>'9')return false;
 return true;
}
static inline int wbq_identity(const uint8_t *data,size_t len,char ver[6]){
 wb_sfo s;char id[sizeof WB_TITLE_ID];
 if(wb_sfo_parse(&s,data,len)!=WB_OK || !wb_sfo_unambiguous(&s) ||
    wb_sfo_get(&s,"TITLE_ID",id,sizeof id)!=WB_OK || strcmp(id,WB_TITLE_ID))return WB_E_TITLE;
 return wb_sfo_get(&s,"APP_VER",ver,6)==WB_OK && wbq_version_ok(ver)?WB_OK:WB_E_VERSION;
}
static inline int wbq_bytes(wbq_manifest *m,unsigned idx,const uint8_t *p,size_t n){
 if(idx>=4 || !p || !n || n>WBQ_FILE_MAX)return WB_E_LIMIT;
 wb_sha256 h;wb_sha256_init(&h);wb_sha256_update(&h,p,n);wb_sha256_final(&h,m->hash[idx]);m->size[idx]=n;return WB_OK;
}
static inline int wbq_format(const wbq_manifest *m,const char *ver,char out[WBQ_CAP]){
 if(!wbq_version_ok(ver))return WB_E_VERSION;
 wb_sha256 h;uint8_t d[32];char hex[65];unsigned long total=0;
 wb_sha256_init(&h);wb_sha256_update(&h,"WBMF2\n",6);
 for(unsigned i=0;i<4;i++){
  if(!m->size[i] || m->size[i]>WBQ_FILE_MAX)return WB_E_LIMIT;
  total+=(unsigned long)m->size[i];uint8_t b[8];
  for(int j=0;j<8;j++)b[7-j]=(uint8_t)(m->size[i]>>(j*8));
  wb_sha256_update(&h,wbq_names[i],strlen(wbq_names[i])+1);
  wb_sha256_update(&h,b,sizeof b);wb_sha256_update(&h,m->hash[i],32);
 }
 wb_sha256_final(&h,d);wb_sha_hex(d,32,hex);
 const int n=snprintf(out,WBQ_CAP,WBQ_PREFIX "%s %s %lu\n",ver,hex,total);
 return n>0 && n<WBQ_CAP?WB_OK:WB_E_FORMAT;
}
#endif
