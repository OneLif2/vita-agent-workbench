#ifndef WB_APP_GATE_IMPL_H
#define WB_APP_GATE_IMPL_H

/* Compiled inside the core (and by the native test harness). Only INAP00020
 * runs test jobs. Other reviewed titles may be installation-only. The registry is
 * independent of any PC-supplied options or files in the upload directory. */
#include "wb_app_registry.h"
#include "wb_err.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_zip.h"

#define WB_APP_SFO_MAX 65536u

#include "wb_app_spool.h"
#ifndef WB_APP_IO_OPS
#error "App installer requires an explicit disk spool adapter"
#endif
#ifndef WB_APP_COOPERATE
#define WB_APP_COOPERATE() ((void)0)
#endif
#ifndef WB_APP_METER
#define WB_APP_METER(phase, done, total) ((void)0)
#endif
#ifndef WB_APP_BUDGET
#error "App installer requires a real free-space query"
#endif
static struct {wb_out *out;const char *phase;uint64_t bytes,total,last;int rc;} wb_app_progress;
static int wb_app_pulse(void) {
    WB_APP_COOPERATE();
    WB_APP_METER(wb_app_progress.phase, wb_app_progress.bytes, wb_app_progress.total);
    const uint64_t now=now_ms();
    if(wb_app_progress.rc!=WB_OK)return wb_app_progress.rc;
    if(wb_app_progress.out && (now<wb_app_progress.last || now-wb_app_progress.last>=1000)){
        wb_app_progress.last=now;
        /* total= is optional. An installed 02.10 core still emits bytes only. */
        if(wb_app_progress.total)
            wb_app_progress.rc=wb_out_printf(wb_app_progress.out,
                "app-progress phase=%s bytes=%llu total=%llu\n",
                wb_app_progress.phase,(unsigned long long)wb_app_progress.bytes,
                (unsigned long long)wb_app_progress.total);
        else
            wb_app_progress.rc=wb_out_printf(wb_app_progress.out,"app-progress phase=%s bytes=%llu\n",
                              wb_app_progress.phase,(unsigned long long)wb_app_progress.bytes);
    }
    return wb_app_progress.rc;
}
static void wb_app_phase(const char *phase, uint64_t total) {
    wb_app_progress.phase=phase;wb_app_progress.bytes=0;wb_app_progress.total=total;
}
static int wb_app_copy_progress(void *ctx,uint64_t n){(void)ctx;wb_app_progress.bytes=n;return wb_app_pulse();}
static int wb_app_count_progress(size_t n){
    if(n>UINT64_MAX-wb_app_progress.bytes)return WB_E_LIMIT;
    wb_app_progress.bytes+=n;return wb_app_pulse();
}

typedef struct { uint8_t *bytes; size_t size; } wb_app_blob;

static int wb_app_err(wb_out *out, const char *label, int rc) {
    (void)wb_out_printf(out, "ERR %s\n", label);
    return rc == WB_OK ? WB_E_STATE : rc;
}

/* Load this file once. Never re-open the upload pathname for extraction:
 * the SFO, digest, CRC and staged bytes must all refer to the same snapshot. */
static int wb_app_snapshot(const char *path, size_t cap, wb_app_blob *snap) {
    wb_vfile f;
    wb_reader rd;
    int rc = wb_vita_reader_open(path, &rd, &f);
    if (rc != WB_OK) return rc;
    if (!rd.size || rd.size > cap) rc = WB_E_LIMIT;
    if (rc == WB_OK) {
        snap->size = (size_t)rd.size;
        snap->bytes = malloc(snap->size);
        if (!snap->bytes) rc = WB_E_NOMEM;
        else rc = rd.read_at(rd.ctx, 0, snap->bytes, snap->size);
    }
    wb_vita_reader_close(&f);
    if (rc != WB_OK) { free(snap->bytes); snap->bytes = NULL; snap->size = 0; }
    return rc;
}

static int wb_app_identity(const uint8_t *bytes, size_t n, char tid[16], char ver[16]) {
    wb_sfo s;
    return wb_sfo_parse(&s, bytes, n) == WB_OK && wb_sfo_unambiguous(&s) &&
           wb_sfo_get(&s, "TITLE_ID", tid, 16) == WB_OK &&
           wb_sfo_get(&s, "APP_VER", ver, 16) == WB_OK ? WB_OK : WB_E_FORMAT;
}

static int wb_app_parse_sfo(wb_zip *zip, char tid[16], char ver[16]) {
    wb_zip_entry e;
    int rc = wb_zip_find(zip, "sce_sys/param.sfo", &e);
    if (rc != WB_OK || !e.usize || e.usize > WB_APP_SFO_MAX || e.csize > zip->rd.size)
        return WB_E_FORMAT;
    uint8_t *data = malloc((size_t)e.usize);
    if (!data) return WB_E_NOMEM;
    size_t n = 0;
    rc = wb_zip_read(zip, &e, data, (size_t)e.usize, &n);
    if (rc == WB_OK) rc = wb_app_identity(data, n, tid, ver);
    free(data);
    return rc;
}

/* Validate compressed payloads, CRC and member/path uniqueness through the
 * same decoder/extractor, but leave the previous stage entirely untouched. */
static int wb_app_no_mkdir(void *ctx, const char *name) { (void)ctx; (void)name; return WB_OK; }
static int wb_app_no_create(void *ctx, const char *name, uint64_t n) { (void)ctx; (void)name; (void)n; return WB_OK; }
static int wb_app_no_write(void *ctx, const void *buf, size_t n) { (void)ctx; (void)buf; return wb_app_count_progress(n); }
static int wb_app_no_close(void *ctx) { (void)ctx; return WB_OK; }

static int wb_app_validate(wb_zip *zip,wb_out *out) {
    wb_zip_entry boot;
    if (wb_zip_find(zip, "eboot.bin", &boot) != WB_OK || !boot.usize) return WB_E_FORMAT;
    unsigned cursor = 0;
    uint64_t total = 0;
    wb_zip_entry e;
    int rc;
    while ((rc = wb_zip_next(zip, &cursor, &e)) == WB_OK) {
        if (e.usize > UINT64_MAX - total || e.csize > zip->rd.size) return WB_E_LIMIT;
        total += e.usize;
    }
    if (rc != 1) return rc;
    /* Account for stage data, generated head and directory/allocation overhead.
     * The archive snapshot already occupies disk and is not counted twice. */
    const uint64_t reserve=UINT64_C(4)*1024*1024+(uint64_t)zip->count*8192u+WB_HEAD_SIZE;
    if(total>UINT64_MAX-reserve)return WB_E_LIMIT;
    rc=WB_APP_BUDGET(total+reserve,out);if(rc!=WB_OK)return rc;
    wb_app_phase("validate", total);
    const wb_writer sink = { .mkdirs=wb_app_no_mkdir, .create=wb_app_no_create,
                             .write=wb_app_no_write, .close=wb_app_no_close };
    return wb_zip_extract_all(zip, &sink, NULL, NULL, NULL);
}

static int wb_app_clear_stage(void) {
    SceIoStat st = {0};
    const int native = sceIoGetstat(WB_APP_STAGE, &st);
    if ((uint32_t)native == UINT32_C(0x80010002)) return WB_OK; /* native ENOENT */
    if (native < 0 || !SCE_S_ISDIR(st.st_mode)) return WB_E_STAGE;
    return wb_vita_remove_tree(WB_APP_STAGE);
}

typedef struct {const wb_writer *base;} wb_app_writer;
static int wb_app_wmkdir(void *ctx,const char *p){const wb_writer *w=((wb_app_writer *)ctx)->base;return w->mkdirs(w->ctx,p);}
static int wb_app_wcreate(void *ctx,const char *p,uint64_t n){const wb_writer *w=((wb_app_writer *)ctx)->base;return w->create(w->ctx,p,n);}
static int wb_app_wwrite(void *ctx,const void *p,size_t n){
    const wb_writer *w=((wb_app_writer *)ctx)->base;int rc=w->write(w->ctx,p,n);
    return rc==WB_OK?wb_app_count_progress(n):rc;
}
static int wb_app_wclose(void *ctx){const wb_writer *w=((wb_app_writer *)ctx)->base;return w->close(w->ctx);}
static int wb_app_materialize(wb_zip *zip, const char *tid, unsigned *files, int *detail) {
    /* The generated head is written through the same counting writer as ZIP
     * members. Include it before touching stage, and never wrap the total. */
    if (wb_app_progress.total > UINT64_MAX - WB_HEAD_SIZE) return WB_E_LIMIT;
    const uint64_t extract_total = wb_app_progress.total + WB_HEAD_SIZE;
    uint8_t head[WB_HEAD_SIZE];
    int rc = wb_head_build(head, sizeof head, tid, NULL);
    if (rc != WB_OK) return rc;
    rc = wb_app_clear_stage();
    if (rc != WB_OK) return rc;
    wb_vwriter w;
    rc = wb_vita_writer_init(&w, WB_APP_STAGE);
    if (rc != WB_OK) return rc;
    wb_app_writer proxy={wb_vita_writer_ops(&w)};
    const wb_writer protected_ops={.ctx=&proxy,.mkdirs=wb_app_wmkdir,.create=wb_app_wcreate,
                                  .write=wb_app_wwrite,.close=wb_app_wclose};
    const wb_writer *ops=&protected_ops;
    wb_app_phase("extract", extract_total);
    wb_zip_stats stats;
    rc = wb_zip_extract_all(zip, ops, &stats, NULL, NULL);
    if (rc == WB_OK) rc = ops->mkdirs(ops->ctx, "sce_sys/package");
    if (rc == WB_OK) rc = ops->create(ops->ctx, "sce_sys/package/head.bin", sizeof head);
    if (rc == WB_OK) {
        rc = ops->write(ops->ctx, head, sizeof head);
        const int close_rc = ops->close(ops->ctx);
        if (rc == WB_OK) rc = close_rc;
    }
    if (rc != WB_OK) return rc; /* partial stage is never promoted */
    *files = stats.files;
    (void)detail;return WB_OK; /* Snapshot cleanup must succeed before promotion. */
}

static int wb_app_operation(const char *path, const char *want_case, bool preview, wb_out *out) {
    if (!wb_install_source_ok(path)) return wb_app_err(out, "path-denied", WB_E_PATH);
    memset(&wb_app_progress,0,sizeof wb_app_progress);wb_app_progress.out=out;
    wb_app_progress.phase="copy";wb_app_progress.last=now_ms();
    wb_app_spool snap={0};wb_vfile input={.fd=-1};wb_reader original;
    int rc=wb_vita_reader_open(path,&original,&input);
    if(rc!=WB_OK)return wb_app_err(out,"app-snapshot",rc);
    if(!original.size || original.size>WB_APP_ARCHIVE_MAX)rc=WB_E_LIMIT;
    else {
        wb_app_progress.total=original.size;
        rc=WB_APP_BUDGET(original.size+UINT64_C(4)*1024*1024,out);
    }
    if(rc==WB_OK)rc=wb_app_spool_copy(&snap,&original,WB_APP_IO_OPS,wb_app_copy_progress,NULL);
    wb_vita_reader_close(&input);
    if(rc!=WB_OK)return wb_app_err(out,"app-snapshot",rc);
    wb_zip zip;char tid[16]={0},ver[16]={0};const char *hex=snap.digest;
    unsigned files=0;int detail=0;const char *why="app-zip";
    rc=wb_zip_open(&zip,&snap.reader);if(rc!=WB_OK)goto end;
    if(!zip.count){rc=WB_E_FORMAT;goto end;}
    why="app-sfo";rc=wb_app_parse_sfo(&zip,tid,ver);if(rc!=WB_OK)goto end;
    wb_reg_result decision = wb_reg_install(tid, ver, hex);
    const wb_reg_entry *row=wb_reg_entry_for(tid,ver);
    /* Two kinds of row can authorize an installation: a compiled catalog row and
     * an owner-signed runtime row. A runtime row carries no cases at all, so it
     * is install-only by construction. Never use this command for the Workbench
     * core, the updater, or arbitrary VPKs. */
    const bool runtime_row = !row && wb_app_local_match(tid, ver, hex) == 1;
    const char *cases = row ? row->cases : "";
    if (decision != WB_REG_OK || (!row && !runtime_row) || !strcmp(tid,WB_TITLE_ID) ||
        !strcmp(tid,WB_UPDATER_TITLE_ID) ||
        (strcmp(tid,WB_TESTAPP_TITLE_ID) && cases[0])) {
        why = decision != WB_REG_OK ? wb_reg_reason(decision) : "registry-title";
        rc = WB_E_STATE; goto end;
    }
    why = "app-members";
    rc = wb_app_validate(&zip,out);
    if (rc != WB_OK) goto end;
    if (preview) {
        if (want_case && wb_reg_launch(tid,ver,want_case)!=WB_REG_OK) {
            why="registry-case";rc=WB_E_STATE;goto end;
        }
        rc=wb_app_spool_dispose(&snap);
        if(rc!=WB_OK)return wb_app_err(out,"app-snapshot-cleanup",rc);
        return wb_out_printf(out,"OK app-plan title=%s app_ver=%s sha256=%s cases=%s action=none\n",
                             tid,ver,hex,cases[0]?cases:"-");
    }
    why = "app-stage-or-promote";
    rc = wb_app_materialize(&zip, tid, &files, &detail);
    if(rc==WB_OK){
        why="app-snapshot-cleanup";rc=wb_app_spool_dispose(&snap);
        if(rc==WB_OK){why="app-stage-or-promote";rc=wb_vita_promote_stage(WB_APP_STAGE,true,&detail);}
    }
end:
    if(snap.tampered)why="app-snapshot-changed";
    if(rc==WB_E_ZIP64)why="zip64-unsupported";
    {const int cleanup=wb_app_spool_dispose(&snap);if(cleanup!=WB_OK){why="app-snapshot-cleanup";rc=cleanup;}}
    if (rc != WB_OK) {
        if (!strcmp(why,"app-stage-or-promote"))
            (void)wb_out_printf(out,"ERR %s rc=%d detail=%d\n",why,rc,detail);
        else (void)wb_out_printf(out,"ERR %s\n",why);
        return rc;
    }
    return wb_out_printf(out,"OK app-install title=%s app_ver=%s files=%u detail=%d session=kept\n",
                         tid,ver,files,detail);
}

static int do_app_install(const char *path, wb_out *out) {
    return wb_app_operation(path,NULL,false,out);
}

static bool wb_app_job_ok(const char *job) {
    if (!job) return false;
    const size_t n = strlen(job);
    if (!n || n > 63u) return false;
    for (size_t i=0; i<n; ++i) {
        const char c=job[i];
        if (!((c>='A' && c<='Z') || (c>='a' && c<='z') ||
              (c>='0' && c<='9') || c=='-' || c=='_')) return false;
    }
    return true;
}

#include "wb_result_record.h"
static inline int wb_terminal_result(const char *cse,const char *job,wb_out *out) {
    if(!wb_app_job_ok(job)||!wb_app_job_ok(cse))return wb_app_err(out,"invalid-case-or-job",WB_E_ARG);
    wb_app_blob blob={0}; /* Never accept a pathname from the command here. */
    char text[1025];const char *assertion=NULL;
    if(wb_app_snapshot(WB_ROOT "/testapp/result.txt",sizeof text-1,&blob)!=WB_OK)
        return wb_app_err(out,"INCONCLUSIVE result-unavailable",WB_E_IO);
    memcpy(text,blob.bytes,blob.size);free(blob.bytes);
    int verdict=wb_rr_check(text,blob.size,WB_TESTAPP_TITLE_ID,cse,job,&assertion);
    if(verdict<0)return wb_app_err(out,"INCONCLUSIVE result-mismatch-or-malformed",WB_E_FORMAT);
    int rc=wb_out_printf(out,"test-result job=%s title=%s case=%s result=%s assert=%s\n",
                         job,WB_TESTAPP_TITLE_ID,cse,verdict?"PASS":"FAIL",assertion);
    return rc<0?rc:verdict?WB_OK:WB_E_STATE;
}

static int do_launch(const char *title, const char *cse, const char *job, wb_out *out) {
    if (!title || strcmp(title, WB_TESTAPP_TITLE_ID) || !wb_reg_has_title(title))
        return wb_app_err(out, "registry-title", WB_E_TITLE);
    wb_app_blob sfo = {0};
    int rc = wb_app_snapshot(WB_TESTAPP_SFO, WB_APP_SFO_MAX, &sfo);
    if (rc != WB_OK) return wb_app_err(out, "testapp-installed-sfo-unavailable", rc);
    char actual[16]={0}, ver[16]={0};
    rc = wb_app_identity(sfo.bytes, sfo.size, actual, ver);
    free(sfo.bytes);
    if (rc != WB_OK) return wb_app_err(out, "app-sfo", rc);
    if (strcmp(actual,title)) return wb_app_err(out, "registry-title", WB_E_TITLE);
    wb_reg_result decision = wb_reg_launch(actual, ver, cse);
    if (decision != WB_REG_OK) return wb_app_err(out, wb_reg_reason(decision), WB_E_STATE);
    if (!wb_app_job_ok(job)) return wb_app_err(out, "invalid-job", WB_E_ARG);
    if(!quick_barrier())return wb_app_err(out,"quick-open-fence",WB_E_IO);
    rc = wb_arm_issue(job,cse);
    if (rc != WB_OK) return wb_app_err(out,"job-arm-storage",rc);
    a.guard_grace = now_ms() + 15000;
    const int launch_rc = sceAppMgrLaunchAppByUri(0xFFFFF, "psgm:play?titleid=" WB_TESTAPP_TITLE_ID);
    if (launch_rc < 0) {
        (void)wb_arm_cancel();
        (void)wb_out_printf(out,"ERR app-launch rc=0x%08X\n",(unsigned)launch_rc);
        return WB_E_STATE;
    }
    return wb_out_printf(out,"OK launch title=%s case=%s job=%s\n",title,cse,job);
}
#endif
