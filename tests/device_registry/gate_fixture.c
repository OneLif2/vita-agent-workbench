/* Exact production B2 gate included below, with ordinary harmless input archives
 * and in-memory Vita operations. Only fixture VPK & fixture SFO are read on host.
 * Host ZIP/SFO/SHA256, decompression, head generation and gate code are real. */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
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
#define WB_TESTAPP_TITLE_ID "INAP00020"
#define WB_TESTAPP_SFO "ux0:app/" WB_TESTAPP_TITLE_ID "/sce_sys/param.sfo"
#define WB_APP_STAGE WB_ROOT "/stage/app"
#define WB_JOB_PATH WB_ROOT "/job.txt"
#define INCOMING WB_INCOMING "/fixture.vpk"
static struct { uint64_t guard_grace; } a;
static uint64_t now_ms(void) {return 7800;}
static unsigned char *pkg,*sf;
static size_t plen,slen,reply_n;
static int clear_calls,mkdir_calls,files,commits,launches,jobs,mutated,closed_input,reading_eboot;
static char reply[2048],seen_eboot[65];
static const char *scenario;
static wb_sha256 ectx;
static int is(const char *s) {return !strcmp(scenario,s);}
static int rd(const void *c,uint64_t off,void *out,size_t n) {
    const wb_vfile *vf=c;assert(vf->fd==10 || vf->fd==11);
    if(vf->fd==10 && is("install-short-read"))return WB_E_IO;
    size_t size=vf->fd==10?plen:slen; const unsigned char *b=vf->fd==10?pkg:sf;
    if(off>size || n>size-off)return WB_E_IO;
    memcpy(out,b+(size_t)off,n);return WB_OK;
}
int wb_vita_reader_open(const char *p,wb_reader *r,wb_vfile *f) {
    if(!strcmp(p,INCOMING)){f->fd=10;r->size=plen;}
    else if(!strcmp(p,WB_TESTAPP_SFO)){f->fd=11;r->size=slen;}
    else if(!strcmp(p,WB_ROOT "/testapp/result.txt")){f->fd=11;r->size=slen;}
    else return WB_E_IO;
    r->read_at=rd;r->ctx=f;return 0;
}
void wb_vita_reader_close(wb_vfile *f) {
    if(f->fd==10) {
        closed_input++;
        if(is("install-snapshot-immutable")) {memset(pkg,0xA5,plen);mutated++;}
    }
    f->fd=-1;
}
int wb_vita_read_small(const char *p,void *buf,size_t cap,size_t *n) {
    if(strcmp(p,WB_TESTAPP_SFO)||slen>cap)return WB_E_IO;
    memcpy(buf,sf,slen);*n=slen;return 0;
}
bool wb_vita_exists(const char *p) { return !strcmp(p,WB_TESTAPP_SFO); }
int sceIoGetstat(const char *p,SceIoStat *s) {
    if(strcmp(p,WB_TESTAPP_SFO))return (int)0x80010002U;
    memset(s,0,sizeof(*s));s->st_size=(SceOff)slen;s->st_mode=0x2000;return 0;
}
int wb_vita_remove_tree(const char *p) {assert(!strcmp(p,WB_APP_STAGE)); ++clear_calls;return 0;}
int wb_vita_mkdir_p(const char *p) {assert(!strncmp(p,WB_APP_STAGE,strlen(WB_APP_STAGE)));++mkdir_calls;return 0;}
int wb_vita_write_file(const char *p,const void *buf,size_t n,bool append) {
    assert(!append && n>0 && buf);
    if(!strcmp(p,WB_JOB_PATH)){assert(n<155);++jobs;return 0;}
    assert(!strncmp(p,WB_APP_STAGE,strlen(WB_APP_STAGE)));files++;return 0;
}
static int mk(void *ctx,const char *p) {(void)ctx;assert(p);++mkdir_calls;return 0;}
static int cr(void *ctx,const char *p,uint64_t n) {
    (void)ctx;assert(n);if(is("install-stage-write-failed"))return WB_E_IO;
    ++files;reading_eboot=!strcmp(p,"eboot.bin");if(reading_eboot)wb_sha256_init(&ectx);return 0;
}
static int wr(void *ctx,const void *data,size_t n) {
    (void)ctx;assert(data);if(reading_eboot)wb_sha256_update(&ectx,data,n);return 0;
}
static int cl(void *ctx) {
    (void)ctx;if(reading_eboot){uint8_t h[32];wb_sha256_final(&ectx,h);wb_sha_hex(h,32,seen_eboot);reading_eboot=0;}return 0;
}
static wb_writer writer={NULL,mk,cr,wr,cl,NULL};
int wb_vita_writer_init(wb_vwriter *w,const char *p) {assert(w && !strcmp(p,WB_APP_STAGE));memset(w,0,sizeof(*w));return 0;}
const wb_writer *wb_vita_writer_ops(wb_vwriter *w) {assert(w);writer.ctx=w;return &writer;}
int wb_vita_promote_stage(const char *p,bool skip,int *detail) {assert(!strcmp(WB_APP_STAGE,p)&&skip);*detail=0;commits++;return 0;}
int sceAppMgrLaunchAppByUri(int flags,const char *uri) {
    assert(flags==0xFFFFF && !strcmp(uri,"psgm:play?titleid=INAP00020"));++launches;return is("launch-platform-failed")?-17:0;
}
static int capture(void *c,const char *s,size_t n){(void)c;assert(n<sizeof reply-reply_n);memcpy(reply+reply_n,s,n);reply_n+=n;reply[reply_n]=0;return 0;}
/* Only the app registry is under test here. S4 has a separate FS/SaveData fixture. */
static bool quick_barrier(void){return true;}
static int wb_arm_issue(const char *job,const char *cse){assert(job&&cse);jobs++;return WB_OK;}
static int wb_arm_cancel(void){return WB_OK;}
#include "../large_app_native/file_spool_fixture.h"
static int fixture_app_budget(uint64_t required,wb_out *out){(void)out;assert(required>0);return WB_OK;}
#define WB_APP_BUDGET(required,out) fixture_app_budget(required,out)
#include "wb_app_gate_impl.h"
static unsigned char *load(const char *p,size_t *n){
    FILE *f=fopen(p,"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);long pos=ftell(f);assert(pos>0 && pos<1000000);
    *n=(size_t)pos;rewind(f);unsigned char *b=malloc(*n);assert(b && fread(b,1,*n,f)==*n);assert(fclose(f)==0);return b;
}
int main(int argc,char **argv){
    assert(argc==5);scenario=argv[1];pkg=load(argv[2],&plen);sf=load(argv[3],&slen);
    wb_out out={NULL,capture};int rc;
    if(!strncmp(scenario,"plan-",5))rc=wb_app_operation(INCOMING,is("plan-case-denied")?"not-reviewed":"fs-smoke",true,&out);
    else if(!strncmp(scenario,"result-",7))rc=wb_terminal_result(is("result-power")?"power-smoke":is("result-compute")?"compute-smoke":"fs-smoke","TEST_0001",&out);
    else if(!strncmp(scenario,"install-",8))rc=do_app_install(INCOMING,&out);
    else rc=do_launch(is("launch-install-only-title-denied")?"VSSH00001":is("launch-title-denied")?"INAP00099":WB_TESTAPP_TITLE_ID,
                      is("launch-case-denied")?"not-approved":"fs-smoke","20261121T170001-ab1234",&out);
    printf("%s rc=%d stage=%d mkdir=%d files=%d promote=%d jobs=%d launch=%d | %s\n",
           scenario,rc,clear_calls,mkdir_calls,files,commits,jobs,launches,reply);fflush(stdout);
    if(!strncmp(scenario,"result-",7)){
        assert(!clear_calls&&!mkdir_calls&&!files&&!commits&&!jobs&&!launches);
        if(is("result-pass")||is("result-power")||is("result-compute"))assert(!rc&&strstr(reply,"result=PASS"));
        else if(is("result-fail"))assert(rc&&strstr(reply,"result=FAIL"));
        else assert(rc && strstr(reply,"INCONCLUSIVE")&&!strstr(reply,"result=PASS"));
    }else if(is("plan-approved")){
        assert(!rc&&strstr(reply,"OK app-plan title=INAP00020 app_ver=01.01")&&strstr(reply,"action=none"));
        assert(!clear_calls&&!mkdir_calls&&!files&&!commits&&!jobs&&!launches);
    }else if(is("install-approved")||is("install-snapshot-immutable")) {
        assert(rc==WB_OK && commits==1 && strstr(reply,"OK app-install title=INAP00020 app_ver=01.01"));
        assert(closed_input==1 && !strcmp(argv[4],seen_eboot));
        if(is("install-snapshot-immutable"))assert(mutated==1);
    }else if(is("install-approved-ssh-vita")) {
        assert(rc==WB_OK && commits==1 && files==12 && !launches && !jobs);
        assert(strstr(reply,"OK app-install title=VSSH00001 app_ver=01.42 files=11"));
        assert(closed_input==1 && !strcmp(argv[4],seen_eboot));
    }else if(is("launch-approved")) {assert(rc==0 && jobs==1 && launches==1 && strstr(reply,"OK launch"));}
    else {
        assert(rc!=0 && strstr(reply,"ERR ") && !strstr(reply,"OK ") && commits==0);
        if(is("launch-platform-failed"))assert(jobs==1 && launches==1);
        else {assert(jobs==0 && launches==0);}
        if(!is("install-stage-write-failed"))assert(clear_calls==0 && mkdir_calls==0 && files==0);
        if(strstr(scenario,"title-denied"))assert(strstr(reply,"ERR registry-title"));
        if(strstr(scenario,"version-denied"))assert(strstr(reply,"ERR registry-version"));
        if(strstr(scenario,"sha-denied"))assert(strstr(reply,"ERR registry-sha256"));
        if(strstr(scenario,"case-denied"))assert(strstr(reply,"ERR registry-case"));
    }
    free(sf);free(pkg);return 0;
}
