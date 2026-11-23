#ifndef WB_CHECKED_HASH_H
#define WB_CHECKED_HASH_H
/* One read path for plan/inspect. A digest becomes valid only after the
 * entire declared length has been consumed successfully. */
#include "wb_zip.h"
#include "wb_sha256.h"
#include "wb_err.h"
#include <stdlib.h>
#include <string.h>

static int wb_checked_hash(const wb_reader *r, char hex[65], void *(*allocate)(size_t)) {
    enum { CHUNK = 4096 };
    uint8_t raw[32], *buf = NULL;
    wb_sha256 sha;
    hex[0] = 0;
    wb_sha256_init(&sha);
    if (r->size) {
        buf = (uint8_t *)allocate(CHUNK);
        if (!buf) return WB_E_NOMEM;
    }
    for (uint64_t off = 0; off < r->size;) {
        const size_t take = (r->size - off > CHUNK) ? CHUNK : (size_t)(r->size - off);
        if (r->read_at(r->ctx, off, buf, take) != WB_OK) {
            free(buf);
            return WB_E_IO;
        }
        wb_sha256_update(&sha, buf, take);
        off += take;
    }
    free(buf);
    wb_sha256_final(&sha, raw);
    wb_sha_hex(raw, sizeof raw, hex);
    return WB_OK;
}

/* Fixed read-only diagnostics: no global allocation hook, no caller-selected
 * inputs, no filesystem operations. Exercise the same reader as both commands. */
static void *wb_s2_no_alloc(size_t n) { (void)n; return NULL; }
static int wb_s2_fixture_read(const void *ctx, uint64_t off, void *out, size_t n) {
    (void)ctx;
    if (off != 0) return WB_E_IO;
    memset(out, 'a', n);
    return WB_OK;
}
static int wb_s2_selftest(void) {
    wb_reader r = { .ctx=NULL, .size=0, .read_at=wb_s2_fixture_read };
    char hex[65];
    if (wb_checked_hash(&r,hex,wb_s2_no_alloc)!=WB_OK ||
        strcmp(hex,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        return WB_E_STATE;
    r.size=1;
    if (wb_checked_hash(&r,hex,malloc)!=WB_OK ||
        strcmp(hex,"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"))
        return WB_E_STATE;
    if (wb_checked_hash(&r,hex,wb_s2_no_alloc)!=WB_E_NOMEM || hex[0]) return WB_E_STATE;
    r.size=4097;
    if (wb_checked_hash(&r,hex,malloc)!=WB_E_IO || hex[0]) return WB_E_STATE;
    return WB_OK;
}
#endif
