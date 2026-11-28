/* The product spool, with host temporary files and tracked product allocations.
 * No Vita calls, sockets or fixture archive retained in RAM. */
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_err.h"
#include "wb_sha256.h"
static size_t live,peak,max_one;
static unsigned allocations;
static void *tracked_malloc(size_t n) {
    size_t *p=malloc(n+sizeof(size_t));if(!p)return NULL;
    *p=n;live+=n;if(live>peak)peak=live;if(n>max_one)max_one=n;allocations++;
    return p+1;
}
static void tracked_free(void *ptr) {
    if(ptr){size_t *p=(size_t *)ptr-1;assert(live>=*p);live-=*p;free(p);}
}
#define malloc tracked_malloc
#define free tracked_free
#include "file_spool_fixture.h"
#undef malloc
#undef free
static int source_read(const void *ctx,uint64_t off,void *data,size_t n) {
    return test_spool_read(ctx,off,data,n);
}
static unsigned ticks;
static int tick(void *ctx,uint64_t bytes){(void)ctx;assert(bytes);ticks++;return WB_OK;}
static int cancel(void *ctx,uint64_t bytes){(void)ctx;(void)bytes;return WB_E_STATE;}
static void verify_original(wb_app_spool *spool,const char *sha) {
    uint8_t block[65536],d[32];char hex[65];wb_sha256 h;wb_sha256_init(&h);
    for(uint64_t off=0;off<spool->reader.size;){
        size_t n=(size_t)(spool->reader.size-off<sizeof block?spool->reader.size-off:sizeof block);
        assert(spool->reader.read_at(spool->reader.ctx,off,block,n)==WB_OK);
        wb_sha256_update(&h,block,n);off+=n;
    }
    wb_sha256_final(&h,d);wb_sha_hex(d,32,hex);assert(!strcmp(hex,sha));
}
int main(int argc,char **argv) {
    assert(argc==5);const char *scenario=argv[1];uint64_t size=strtoull(argv[3],NULL,10);
    FILE *input=fopen(argv[2],"rb");assert(input);
    wb_reader src={.ctx=input,.size=size,.read_at=source_read};wb_app_spool spool;
    test_spool_begin_fail=!strcmp(scenario,"begin-fail");
    test_spool_write_fail=!strcmp(scenario,"write-fail");
    test_spool_finish_fail=!strcmp(scenario,"finish-fail");
    int rc=wb_app_spool_copy(&spool,&src,&test_spool_ops,!strcmp(scenario,"cancel")?cancel:tick,NULL);
    assert(fclose(input)==0);
    if(test_spool_begin_fail || test_spool_write_fail || test_spool_finish_fail || !strcmp(scenario,"cancel")) {
        assert(rc!=WB_OK && live==0 && test_spool_opens==test_spool_closes);
    }else {
        assert(rc==WB_OK && ticks>0 && !strcmp(spool.digest,argv[4]));
        if(!strcmp(scenario,"tampered-spool")) {
            uint8_t changed=0xa7,out=0;
            assert(test_seek(test_spool_file,WB_APP_BLOCK+17)==0);
            assert(fwrite(&changed,1,1,test_spool_file)==1 && fflush(test_spool_file)==0);
            assert(spool.reader.read_at(spool.reader.ctx,WB_APP_BLOCK+17,&out,1)!=WB_OK);
            assert(spool.tampered && !spool.valid);
        }else if(!strcmp(scenario,"mutated-source")) {
            /* Source pathname bytes may change once the protected snapshot exists. */
            FILE *changed=fopen(argv[2],"wb");assert(changed);assert(fwrite("changed",1,7,changed)==7);assert(!fclose(changed));
            verify_original(&spool,argv[4]);
        }else if(!strcmp(scenario,"dispose-fail"))test_spool_dispose_fail=true;
        else verify_original(&spool,argv[4]);
        int dispose=wb_app_spool_dispose(&spool);
        assert(dispose==(test_spool_dispose_fail?WB_E_IO:WB_OK));
        assert(live==0 && test_spool_opens==test_spool_closes);
    }
    assert(peak<=2u*1024u*1024u && max_one<=2u*1024u*1024u);
    printf("PASS protected-spool %s bytes=%llu rc=%d peak=%zu max_allocation=%zu allocations=%u handles=%u/%u ticks=%u\n",
           scenario,(unsigned long long)size,rc,peak,max_one,allocations,test_spool_opens,test_spool_closes,ticks);
    return 0;
}
