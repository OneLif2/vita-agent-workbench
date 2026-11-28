/* Real app gate + decoder/CRC/head/registry, disk input and protected tmp spool.
 * Runtime row is fixture-injected, NOT proof of a new owner's signature. */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psp2/appmgr.h>
#include <psp2/io/stat.h>
#include "wb_err.h"
#include "wb_head.h"
#include "wb_out.h"
#include "wb_path.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_str.h"
#include "wb_ver.h"
#include "wb_vita_install.h"
#include "wb_zip.h"
#undef malloc
#undef calloc
#undef free
static size_t live,peak,max_one;
void *wb_test_malloc(size_t n){
    size_t *p=malloc(n+sizeof *p);if(!p)return NULL;*p=n;
    live+=n;if(live>peak)peak=live;if(n>max_one)max_one=n;return p+1;
}
void *wb_test_calloc(size_t count,size_t n){
    if(n && count>SIZE_MAX/n)return NULL;
    void *p=wb_test_malloc(count*n);if(p)memset(p,0,count*n);return p;
}
void wb_test_free(void *ptr){if(ptr){size_t *p=(size_t *)ptr-1;assert(*p<=live);live-=*p;free(p);}}
#define malloc wb_test_malloc
#define calloc wb_test_calloc
#define free wb_test_free
#include "file_spool_fixture.h"
#define WB_TESTAPP_TITLE_ID "INAP00020"
#define WB_TESTAPP_SFO "ux0:app/INAP00020/sce_sys/param.sfo"
#define WB_APP_STAGE WB_ROOT "/stage/app"
#define WB_JOB_PATH WB_ROOT "/job.txt"
#define INCOMING WB_INCOMING "/fixture.vpk"
#define LARGE_TITLE "LARG12345"
#define LARGE_VERSION "01.00"
static struct {uint64_t guard_grace;} a;
static const char *scenario,*source_path;
static uint64_t source_size,written;
static FILE *source;
static unsigned source_closes,stage_changes,files,promotes,budgets,progress_count,progress_with_total,source_mutations;
static uint64_t required[2],phase_bytes,phase_totals[3],phase_last[3];
static int phase_index=-1;
static char reply[2048];
static bool is(const char *s){return !strcmp(scenario,s);}
static uint64_t now_ms(void){static uint64_t now;now+=1001;return now;}
static int source_read(const void *ctx,uint64_t off,void *data,size_t n){
    (void)ctx;if(!source || off>source_size || n>source_size-off)return WB_E_IO;
    return test_seek(source,off) || fread(data,1,n,source)!=n?WB_E_IO:WB_OK;
}
int wb_vita_reader_open(const char *path,wb_reader *reader,wb_vfile *vf){
    if(strcmp(path,INCOMING))return WB_E_IO;
    source=fopen(source_path,"rb");if(!source)return WB_E_IO;vf->fd=10;
    *reader=(wb_reader){.ctx=vf,.size=source_size,.read_at=source_read};return WB_OK;
}
static void tamper_spool(void){
    uint8_t value=0xa7;assert(test_spool_file && test_seek(test_spool_file,WB_APP_BLOCK+17)==0);
    assert(fwrite(&value,1,1,test_spool_file)==1 && !fflush(test_spool_file));
}
void wb_vita_reader_close(wb_vfile *vf){
    assert(vf->fd==10 && source);assert(!fclose(source));source=NULL;vf->fd=-1;source_closes++;
    if(is("source-mutated")){
        FILE *file=fopen(source_path,"wb");assert(file && fwrite("changed",1,7,file)==7 && !fclose(file));source_mutations++;
    }
    if(is("spool-mutated-before-validate"))tamper_spool();
}
int wb_vita_read_small(const char *p,void *b,size_t c,size_t *n){(void)p;(void)b;(void)c;(void)n;return WB_E_IO;}
bool wb_vita_exists(const char *p){(void)p;return false;}
int sceIoGetstat(const char *p,SceIoStat *st){
    assert(!strcmp(p,WB_APP_STAGE));memset(st,0,sizeof *st);return (int)0x80010002u;
}
int wb_vita_remove_tree(const char *p){assert(!strcmp(p,WB_APP_STAGE));stage_changes++;return WB_OK;}
int wb_vita_mkdir_p(const char *p){(void)p;stage_changes++;return WB_OK;}
int wb_vita_write_file(const char *p,const void *b,size_t n,bool append){(void)p;(void)b;(void)n;(void)append;assert(!"unexpected direct write");return WB_E_IO;}
static int mkdirs(void *c,const char *p){(void)c;assert(p);return WB_OK;}
static int create(void *c,const char *p,uint64_t n){(void)c;assert(p&&n);files++;return WB_OK;}
static int write_data(void *c,const void *p,size_t n){(void)c;assert(p&&n);written+=n;return WB_OK;}
static int close_data(void *c){(void)c;return WB_OK;}
static const wb_writer writer={NULL,mkdirs,create,write_data,close_data,NULL};
int wb_vita_writer_init(wb_vwriter *w,const char *p){
    assert(!strcmp(p,WB_APP_STAGE));memset(w,0,sizeof *w);stage_changes++;
    if(is("spool-mutated-after-validate"))tamper_spool();
    return WB_OK;
}
const wb_writer *wb_vita_writer_ops(wb_vwriter *w){assert(w);return &writer;}
int wb_vita_promote_stage(const char *p,bool skip,int *detail){
    assert(!strcmp(p,WB_APP_STAGE)&&skip&&!test_spool_file);promotes++;*detail=0;return WB_OK;
}
int sceAppMgrLaunchAppByUri(int flags,const char *uri){(void)flags;(void)uri;assert(!"never launch");return -1;}
static bool quick_barrier(void){return true;}
static int wb_arm_issue(const char *j,const char *c){(void)j;(void)c;assert(!"never issue job");return WB_E_IO;}
static int wb_arm_cancel(void){assert(!"never cancel job");return WB_E_IO;}
static int budget(uint64_t need,wb_out *out){
    (void)out;assert(need>0 && budgets<2);required[budgets++]=need;
    return (is("snapshot-no-space") && budgets==1) || (is("stage-no-space") && budgets==2)?WB_E_LIMIT:WB_OK;
}
#define WB_APP_BUDGET(need,out) budget(need,out)
#define WB_APP_LOCAL_NO_MBEDTLS 1
#include "wb_app_gate_impl.h"
static int capture(void *ctx,const char *s,size_t n){
    (void)ctx;assert(n<sizeof reply);
    if(n>=13 && !memcmp(s,"app-progress ",13)){
        char phase[16],extra;unsigned long long bytes=0,total=0;
        char line[160];assert(n<sizeof line);memcpy(line,s,n);line[n]=0;
        /* 3 = bytes plus optional total=; 2 = the 02.10 bytes-only line. Trailing junk fails both. */
        int got=sscanf(line,"app-progress phase=%15s bytes=%llu total=%llu %c",phase,&bytes,&total,&extra);
        if(got!=3)got=sscanf(line,"app-progress phase=%15s bytes=%llu %c",phase,&bytes,&extra);
        assert(got==2 || got==3);
        if(got==3){progress_with_total++;assert(bytes<=total);}
        int index=!strcmp(phase,"copy")?0:!strcmp(phase,"validate")?1:!strcmp(phase,"extract")?2:-1;
        assert(index>=0 && index<3);
        if(index==phase_index)assert(total==phase_totals[index]);
        phase_totals[index]=total;phase_last[index]=bytes;
        assert(index>=phase_index && (index!=phase_index || bytes>=phase_bytes));phase_index=index;phase_bytes=bytes;progress_count++;
    }else{memcpy(reply,s,n);reply[n]=0;}
    return WB_OK;
}
int main(int argc,char **argv){
    assert(argc==5);scenario=argv[1];source_path=argv[2];source_size=strtoull(argv[3],NULL,10);
    (void)do_launch;
    /* A forged/overflowed denominator must fail before any stage mutation or
     * writer initialization, even when the supplied ZIP is unusable. */
    wb_zip unused_zip={0};unsigned unused_files=0;int unused_detail=0;
    wb_app_progress.total=UINT64_MAX-WB_HEAD_SIZE+1;
    assert(wb_app_materialize(&unused_zip,LARGE_TITLE,&unused_files,&unused_detail)==WB_E_LIMIT);
    assert(!stage_changes && !files && !written && !promotes && !unused_files);
    const char *sha=argv[4];
    if(!is("title-denied"))assert(wb_app_local_add(LARGE_TITLE,is("version-denied")?"01.01":LARGE_VERSION,
                                                 is("sha-denied")?"0000000000000000000000000000000000000000000000000000000000000000":sha));
    test_spool_dispose_fail=is("cleanup-failed");
    wb_out out={NULL,capture};int rc=is("plan")?wb_app_operation(INCOMING,NULL,true,&out):do_app_install(INCOMING,&out);
    bool ok=is("install") || is("source-mutated") || is("plan");
    assert(source_closes==1 && live==0 && test_spool_opens==test_spool_closes);
    assert(progress_with_total==progress_count);
    assert(peak<2u*1024u*1024u && max_one<2u*1024u*1024u);
    if(ok){
        assert(rc==WB_OK && strstr(reply,is("plan")?"OK app-plan":"OK app-install"));
        assert(budgets==2 && required[0]>source_size && required[1]>193u*1024u*1024u);
        assert(phase_totals[0]==source_size && phase_last[0]==source_size);
        assert(phase_totals[1]==phase_last[1]);
        if(is("plan"))assert(!promotes && !stage_changes && !files && !phase_totals[2]);
        else {
            assert(promotes==1 && files==304 && written>193u*1024u*1024u);
            assert(phase_totals[2]==phase_totals[1]+WB_HEAD_SIZE);
            assert(phase_last[2]==phase_totals[2] && written==phase_totals[2]);
        }
        if(is("source-mutated"))assert(source_mutations==1);
    }else{
        assert(rc!=WB_OK && !promotes && strstr(reply,"ERR "));
        if(is("spool-mutated-before-validate") || is("spool-mutated-after-validate"))assert(strstr(reply,"app-snapshot-changed"));
        if(is("sha-denied"))assert(strstr(reply,"registry-sha256"));
        if(is("title-denied"))assert(strstr(reply,"registry-title"));
        if(is("version-denied"))assert(strstr(reply,"registry-version"));
        if(!is("spool-mutated-after-validate") && !is("cleanup-failed"))assert(!stage_changes && !files);
    }
    printf("PASS large-native-gate %s rc=%d bytes=%llu files=%u written=%llu promote=%u budgets=%u peak=%zu max_alloc=%zu progress=%u | %s",
           scenario,rc,(unsigned long long)source_size,files,(unsigned long long)written,promotes,budgets,peak,max_one,progress_count,reply);
    if(ok)printf("PASS progress-totals %s copy=%llu validate=%llu extract=%llu head=%u overflow_rejected_before_stage=1\n",
                 scenario,(unsigned long long)phase_totals[0],(unsigned long long)phase_totals[1],
                 (unsigned long long)phase_totals[2],WB_HEAD_SIZE);
    return 0;
}
