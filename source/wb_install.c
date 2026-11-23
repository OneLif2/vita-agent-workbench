#include "wb_install.h"
#include "wb_queued.h"

#include "wb_err.h"
#include "wb_head.h"
#include "wb_path.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_str.h"
#include "wb_ver.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SFO_MAX 65536u
#define PAYLOAD_ENTRY "workbench_payload.suprx"

static void sayf(const wb_inst_backend *b, void *ctx, const char *fmt, ...) {
    if (!b || !b->say) return;
    char line[192];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) b->say(ctx, line);
}

typedef struct {
    const wb_inst_backend *backend;
    void *ctx;
} prog_ctx;

static void progress(void *cookie, const wb_zip_stats *st, const char *name) {
    const prog_ctx *p = (const prog_ctx *)cookie;
    (void)st;
    sayf(p->backend, p->ctx, "  + %s\n", name);
}

static int fail(wb_inst_result *res, const wb_inst_backend *b, void *ctx, int code, const char *detail) {
    res->code = code;
    wb_strcpy(res->detail, sizeof res->detail, detail);
    sayf(b, ctx, "install: %s (%s)\n", detail, wb_err_name(code));
    return code;
}

static int mem_read(const void *ctx,uint64_t off,void *out,size_t n){
 const wb_reader *m=(const wb_reader *)ctx;
 if(off>m->size || n>m->size-off)return WB_E_LIMIT;
 memcpy(out,(const uint8_t *)m->ctx+(size_t)off,n);return WB_OK;
}

/* Parse, authenticate and extract only an immutable copy, never a pathname reopened later.
 * Fixed three-file Workbench VPK schema. The generated head becomes the fourth receipt member. */
int wb_install_run(const wb_inst_request *req,const wb_inst_backend *b,void *ctx,wb_inst_result *res){
 if(!req||!b||!res||!req->vpk||!b->open_vpk||!b->close_vpk||!b->stage_reset||
    !b->writer||!b->save_head||!b->seal_stage)return WB_E_ARG;
 memset(res,0,sizeof *res);
 if(!req->sha256 || strlen(req->sha256)!=64)return fail(res,b,ctx,WB_E_SHA,"expected VPK sha256 required");
 if(req->force || req->promote || req->allow_other_title || !wbq_version_ok(req->running_ver))
  return fail(res,b,ctx,WB_E_STATE,"use newer core with queued verified updater");
 const char *slash=strrchr(req->vpk,'/');
 if(!wb_path_name_ok(slash?slash+1:req->vpk))return fail(res,b,ctx,WB_E_PATH,"invalid package name");
 wb_reader f={0};int rc=b->open_vpk(ctx,req->vpk,&f);
 if(rc)return fail(res,b,ctx,rc,"cannot open package");
 if(f.size<22 || f.size>WBQ_INPUT_MAX){b->close_vpk(ctx);return fail(res,b,ctx,WB_E_LIMIT,"package size out of range");}
 const size_t sz=(size_t)f.size;uint8_t *raw=malloc(sz);
 rc=raw?f.read_at(f.ctx,0,raw,sz):WB_E_NOMEM;b->close_vpk(ctx);
 if(rc){free(raw);return fail(res,b,ctx,rc,"snapshot read failed");}
 wb_sha256 h;uint8_t digest[32];char hex[65];
 wb_sha256_init(&h);wb_sha256_update(&h,raw,sz);wb_sha256_final(&h,digest);wb_sha_hex(digest,32,hex);
 if(wb_icmp(req->sha256,hex)){free(raw);return fail(res,b,ctx,WB_E_SHA,"package hash mismatch");}
 const wb_reader data={.ctx=raw,.size=sz}, rd={.ctx=&data,.size=sz,.read_at=mem_read};
 wb_zip z;wbq_manifest expected={0};uint8_t head[WB_HEAD_SIZE];char cid[64]={0},receipt[WBQ_CAP];const char *why="invalid core package";
 rc=wb_zip_open(&z,&rd);if(rc)goto end;
 if(z.count!=3){rc=WB_E_FORMAT;goto end;}
 for(unsigned i=0;i<4;i++){
  if(i==2)continue;
  wb_zip_entry e;rc=wb_zip_find(&z,wbq_names[i],&e);if(rc)goto end;
  if(!e.usize || e.usize>WBQ_FILE_MAX || (i==1 && e.usize>SFO_MAX)){rc=WB_E_LIMIT;goto end;}
  uint8_t *buf=malloc((size_t)e.usize);if(!buf){rc=WB_E_NOMEM;goto end;}
  size_t n=0;rc=wb_zip_read(&z,&e,buf,(size_t)e.usize,&n);
  if(!rc)rc=wbq_bytes(&expected,i,buf,n);
  if(!rc && i==1){
   wb_sfo sfo;rc=wbq_identity(buf,n,res->version);
   if(!rc){wb_strcpy(res->titleid,sizeof res->titleid,WB_TITLE_ID);rc=wb_sfo_parse(&sfo,buf,n);}
   if(!rc)(void)wb_sfo_get(&sfo,"CONTENT_ID",cid,sizeof cid);
   if(!rc && strcmp(res->version,req->running_ver)<=0){rc=WB_E_VERSION;why="package is not newer";}
  }
  free(buf);if(rc)goto end;
 }
 rc=wb_head_build(head,sizeof head,WB_TITLE_ID,cid);
 if(!rc)rc=wbq_bytes(&expected,2,head,sizeof head);
 if(!rc)rc=wbq_format(&expected,res->version,receipt);
 if(rc)goto end;
 why="cannot prepare stage";rc=b->stage_reset(ctx);if(rc)goto end;
 wb_zip_stats stats={0};prog_ctx pc={b,ctx};
 rc=wb_zip_extract_all(&z,b->writer(ctx),&stats,progress,&pc);if(rc)goto end;
 rc=b->save_head(ctx,head,sizeof head);if(rc)goto end;
 res->files=stats.files;res->bytes=stats.bytes;
 why="stage verification / receipt failed";rc=b->seal_stage(ctx,receipt,req->running_ver);if(rc)goto end;
 if(req->reload && b->install_payload){
  why="payload swap failed";rc=b->install_payload(ctx,PAYLOAD_ENTRY,res->payload_ver,sizeof res->payload_ver);if(rc)goto end;
  res->reloaded=true;
 }
 wb_strcpy(res->detail,sizeof res->detail,"verified core queued");
 sayf(b,ctx,"install: WBQ2 core staged and verified\n");
end:
 free(raw);if(rc)return fail(res,b,ctx,rc,why);return WB_OK;
}

