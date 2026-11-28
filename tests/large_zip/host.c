/* Native host-only harness. No device access. Allocation instrumentation covers
 * wb_zip / wb_inflate translation units, not fixture generation / libc FILE. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "wb_zip.h"
#include "wb_err.h"

typedef struct { void *p; size_t n; } allocation;
static allocation allocations[32];
static uint64_t live_bytes, peak_bytes, largest_alloc, max_read;
void *test_malloc(size_t n) {
    void *p = malloc(n);
    if (!p) return NULL;
    for (unsigned i=0;i<32;i++) if (!allocations[i].p) {
        allocations[i].p=p; allocations[i].n=n; live_bytes+=n;
        if (live_bytes>peak_bytes) peak_bytes=live_bytes;
        if (n>largest_alloc) largest_alloc=n;
        return p;
    }
    free(p); return NULL;
}
void *test_calloc(size_t n,size_t size) {
    if (size && n>SIZE_MAX/size) return NULL;
    void *p=test_malloc(n*size); if(p) memset(p,0,n*size); return p;
}
void test_free(void *p) {
    if(!p) return;
    for(unsigned i=0;i<32;i++) if(allocations[i].p==p) {
        live_bytes-=allocations[i].n; allocations[i].p=NULL; free(p); return;
    }
    abort();
}
typedef struct { FILE *f; uint64_t size,fail_at; int read_failure; } source;
static int read_at(const void *ctx,uint64_t off,void *buf,size_t n) {
    source *s=(source*)ctx;
    if(n>max_read) max_read=n;
    if(s->read_failure && off>=s->fail_at) return WB_E_IO;
    if(off>s->size || n>s->size-off) return WB_E_PARTIAL;
#ifdef _WIN32
    if(_fseeki64(s->f,(int64_t)off,SEEK_SET)) return WB_E_IO;
#else
    if(fseeko(s->f,(off_t)off,SEEK_SET)) return WB_E_IO;
#endif
    return fread(buf,1,n,s->f)==n ? WB_OK : WB_E_PARTIAL;
}
typedef struct { uint64_t bytes,expected,max_write; unsigned creates,closes,dirs; int fail,readfail; source *src; } dest;
static int create(void *ctx,const char *name,uint64_t n) {
    dest *d=ctx; (void)name; d->creates++; d->expected+=n;
    if(d->readfail) {d->src->read_failure=1;d->src->fail_at=16384u;}
    return d->fail==2?WB_E_IO:WB_OK;
}
static int sink(void *ctx,const void *buf,size_t n) {
    dest *d=ctx; (void)buf;
    if(n>d->max_write) d->max_write=n;
    if(d->fail==1) return WB_E_IO;
    d->bytes+=n; return WB_OK;
}
static int close_file(void *ctx) { dest *d=ctx;d->closes++;return d->fail==3?WB_E_IO:WB_OK; }
static int mkdirs(void *ctx,const char *name) { dest *d=ctx;(void)name;d->dirs++;return WB_OK; }
int main(int argc,char **argv) {
    if(argc<3) return 2;
    source src={0}; src.f=fopen(argv[1],"rb"); if(!src.f) return 3;
#ifdef _WIN32
    _fseeki64(src.f,0,SEEK_END);src.size=(uint64_t)_ftelli64(src.f);
#else
    fseeko(src.f,0,SEEK_END);src.size=(uint64_t)ftello(src.f);
#endif
    int expected=atoi(argv[2]), rc;
    wb_reader rd={&src,src.size,read_at}; wb_zip z; dest d={0}; wb_zip_stats st={0};
    if(argc>3)d.fail=atoi(argv[3]);
    rc=wb_zip_open(&z,&rd);
    if(!rc) {
        max_read=0;
        if(argc>4 && atoi(argv[4])) {d.readfail=1;d.src=&src;}
        wb_writer w={.ctx=&d,.mkdirs=mkdirs,.create=create,.write=sink,.close=close_file};
        rc=wb_zip_extract_all(&z,&w,&st,NULL,NULL);
    }
    fclose(src.f);
    printf("rc=%d expected=%d files=%u dirs=%u bytes=%" PRIu64 " sink=%" PRIu64
           " creates=%u closes=%u peak_alloc=%" PRIu64 " largest_alloc=%" PRIu64
           " live_alloc=%" PRIu64 " max_read=%" PRIu64 " max_write=%" PRIu64 "\n",
           rc,expected,st.files,st.dirs,st.bytes,d.bytes,d.creates,d.closes,
           peak_bytes,largest_alloc,live_bytes,max_read,d.max_write);
    if(live_bytes || rc!=expected || d.max_write>16384u) return 1;
    if(rc==WB_OK && (st.bytes!=d.bytes || d.bytes!=d.expected || d.closes!=d.creates))return 1;
    if(rc!=WB_OK && st.files) return 1;
    return 0;
}
