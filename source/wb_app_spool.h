#ifndef WB_APP_SPOOL_H
#define WB_APP_SPOOL_H
#include <stdlib.h>
#include <string.h>
#include "wb_zip.h"
#include "wb_sha256.h"
#include "wb_err.h"

/* ZIP32 format ceiling, not a small-app quota. A block manifest retains the
 * original RAM-snapshot trust boundary without holding the archive in RAM:
 * every byte returned to ZIP comes from a block hashed before it is used.
 * An open FD alone does NOT protect against in-place writes. */
#define WB_APP_ARCHIVE_MAX UINT64_C(0xfffffffe)
#define WB_APP_BLOCK 65536u
typedef struct {
    void *ctx;
    int (*begin)(void *,uint64_t,void **);
    int (*write)(void *,const void *,size_t);
    int (*finish)(void *,wb_reader *);
    int (*dispose)(void *);
} wb_app_spool_ops;
typedef struct {
    wb_reader reader,raw;
    const wb_app_spool_ops *ops;
    void *file;
    uint8_t *hashes,*block;
    uint64_t cached;
    bool valid,tampered;
    char digest[65];
} wb_app_spool;
typedef int (*wb_app_copy_tick)(void *,uint64_t);

static inline int wb_app_spool_dispose(wb_app_spool *s) {
    int rc=WB_OK;
    if(s->file){rc=s->ops->dispose(s->file);s->file=NULL;}
    free(s->hashes);free(s->block);s->hashes=s->block=NULL;s->valid=false;
    return rc;
}
static inline int wb_app_spool_read(const void *ctx,uint64_t off,void *dst,size_t n) {
    wb_app_spool *s=(wb_app_spool *)ctx;
    if(off>s->reader.size || n>s->reader.size-off)return WB_E_IO;
    uint8_t *to=dst;
    while(n){
        const uint64_t index=off/WB_APP_BLOCK,base=index*WB_APP_BLOCK;
        if(!s->valid || s->cached!=index){
            const size_t len=(size_t)(s->reader.size-base<WB_APP_BLOCK?s->reader.size-base:WB_APP_BLOCK);
            s->valid=false;
            int rc=s->raw.read_at(s->raw.ctx,base,s->block,len);
            if(rc!=WB_OK)return rc;
            wb_sha256 h;uint8_t d[32];wb_sha256_init(&h);wb_sha256_update(&h,s->block,len);wb_sha256_final(&h,d);
            if(memcmp(d,s->hashes+(size_t)index*32u,32)){s->tampered=true;return WB_E_FORMAT;}
            s->cached=index;s->valid=true;
        }
        size_t take=WB_APP_BLOCK-(size_t)(off-base);if(take>n)take=n;
        memcpy(to,s->block+(size_t)(off-base),take);off+=take;to+=take;n-=take;
    }
    return WB_OK;
}
static inline int wb_app_spool_copy(wb_app_spool *s,const wb_reader *src,
        const wb_app_spool_ops *ops,wb_app_copy_tick tick,void *tick_ctx) {
    memset(s,0,sizeof *s);s->ops=ops;
    if(!src || !src->read_at || !src->size || src->size>WB_APP_ARCHIVE_MAX)return WB_E_LIMIT;
    const uint64_t count=(src->size+WB_APP_BLOCK-1u)/WB_APP_BLOCK;
    if(count>SIZE_MAX/32u)return WB_E_LIMIT;
    s->hashes=malloc((size_t)count*32u);s->block=malloc(WB_APP_BLOCK);
    if(!s->hashes || !s->block){wb_app_spool_dispose(s);return WB_E_NOMEM;}
    int rc=ops->begin(ops->ctx,src->size,&s->file);
    wb_sha256 all;wb_sha256_init(&all);
    for(uint64_t off=0;rc==WB_OK && off<src->size;){
        const size_t n=(size_t)(src->size-off<WB_APP_BLOCK?src->size-off:WB_APP_BLOCK);
        rc=src->read_at(src->ctx,off,s->block,n);if(rc!=WB_OK)break;
        wb_sha256 h;wb_sha256_init(&h);wb_sha256_update(&h,s->block,n);
        wb_sha256_final(&h,s->hashes+(size_t)(off/WB_APP_BLOCK)*32u);
        wb_sha256_update(&all,s->block,n);rc=ops->write(s->file,s->block,n);
        off+=n;if(rc==WB_OK && tick)rc=tick(tick_ctx,off);
    }
    if(rc==WB_OK)rc=ops->finish(s->file,&s->raw);
    if(rc==WB_OK && s->raw.size!=src->size)rc=WB_E_IO;
    if(rc==WB_OK){
        uint8_t d[32];wb_sha256_final(&all,d);wb_sha_hex(d,32,s->digest);
        s->reader=(wb_reader){.ctx=s,.size=src->size,.read_at=wb_app_spool_read};
        s->valid=false;
    }else{const int cleanup=wb_app_spool_dispose(s);if(cleanup!=WB_OK)rc=cleanup;}
    return rc;
}
#endif
