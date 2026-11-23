#include "wb_zip.h"
#include "wb_crc32.h"
#include "wb_err.h"
#include "wb_inflate.h"

#include <stdlib.h>
#include <string.h>

enum {
    SIG_LOCAL   = 0x04034b50u,
    SIG_CENTRAL = 0x02014b50u,
    SIG_EOCD    = 0x06054b50u
};

#define WB_ZIP_MAX_COMPRESSED (WB_ZIP_MAX_FILE + 1024u * 1024u)

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool wb_zip_name_ok(const char *name) {
    if (!name || !*name) return false;
    const size_t len = strlen(name);
    if (len > WB_ZIP_NAME_MAX) return false;
    if (name[0] == '/' || name[0] == '\\') return false;
    for (const char *p = name; *p; p++) {
        const unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c >= 0x7f) return false;
        if (c == '\\' || c == ':') return false;
    }
    /* Reject any ".." component, including trailing forms. */
    const char *p = name;
    while (*p) {
        const char *end = strchr(p, '/');
        const size_t clen = end ? (size_t)(end - p) : strlen(p);
        if (clen == 0) return false;
        if (p[clen - 1] == '.' || p[clen - 1] == ' ') return false;
        if (!end) break;
        p = end + 1;
    }
    return true;
}

static int find_eocd(const wb_reader *rd, uint64_t *cd_off, uint64_t *cd_size, unsigned *count) {
    const uint64_t scan = rd->size < 66560u ? rd->size : 66560u;
    if (scan < 22) return WB_E_FORMAT;
    uint8_t *tail = (uint8_t *)malloc((size_t)scan);
    if (!tail) return WB_E_NOMEM;
    int rc = rd->read_at(rd->ctx, rd->size - scan, tail, (size_t)scan);
    if (rc != WB_OK) { free(tail); return rc; }
    int found = WB_E_FORMAT;
    for (size_t i = (size_t)scan - 22 + 1; i-- > 0;) {
        if (le32(tail + i) != SIG_EOCD) continue;
        const unsigned entries = le16(tail + i + 10);
        const uint64_t csize = le32(tail + i + 12);
        const uint64_t coff  = le32(tail + i + 16);
        const unsigned comment = le16(tail + i + 20);
        if (i + 22u + comment != scan) continue;
        if (le16(tail + i + 4) || le16(tail + i + 6) ||
            le16(tail + i + 8) != entries) continue;
        if (coff + csize != rd->size - scan + i) continue;
        *cd_off = coff; *cd_size = csize; *count = entries;
        found = WB_OK;
        break;
    }
    free(tail);
    return found;
}

int wb_zip_open(wb_zip *z, const wb_reader *rd) {
    if (!z || !rd || !rd->read_at) return WB_E_ARG;
    memset(z, 0, sizeof *z);
    z->rd = *rd;
    int rc = find_eocd(rd, &z->cd_off, &z->cd_size, &z->count);
    if (rc != WB_OK) return rc;
    if (z->count > WB_ZIP_MAX_ENTRIES) return WB_E_LIMIT;
    return WB_OK;
}

static int read_central_entry(wb_zip *z, uint64_t *position, wb_zip_entry *e) {
    const uint64_t pos = *position;
    const uint64_t cd_end = z->cd_off + z->cd_size;
    uint8_t hdr[46];
    if (pos > cd_end || cd_end - pos < sizeof hdr) return WB_E_FORMAT;
    int rc = z->rd.read_at(z->rd.ctx, pos, hdr, sizeof hdr);
    if (rc != WB_OK) return rc;
    if (le32(hdr) != SIG_CENTRAL) return WB_E_FORMAT;
    const unsigned namelen = le16(hdr + 28);
    if (namelen == 0 || namelen > WB_ZIP_NAME_MAX) return WB_E_LIMIT;
    const unsigned extralen = le16(hdr + 30);
    const unsigned commentlen = le16(hdr + 32);
    const uint64_t record_end = pos + sizeof hdr + namelen + extralen + commentlen;
    if (record_end > cd_end || le16(hdr + 34) != 0) return WB_E_FORMAT;
    memset(e, 0, sizeof *e);
    rc = z->rd.read_at(z->rd.ctx, pos + 46u, e->name, namelen);
    if (rc != WB_OK) return rc;
    if (memchr(e->name, 0, namelen)) return WB_E_PATH;
    e->name[namelen] = 0;
    e->flags  = le16(hdr + 8);
    e->method = le16(hdr + 10);
    e->crc    = le32(hdr + 16);
    e->csize  = le32(hdr + 20);
    e->usize  = le32(hdr + 24);
    e->lho    = le32(hdr + 42);
    if (e->usize == 0xffffffffu || e->csize == 0xffffffffu) return WB_E_UNSUPPORTED; /* zip64 */
    if (e->flags & 0x0001u) return WB_E_UNSUPPORTED; /* encrypted */
    if (e->method != 0 && e->method != 8) return WB_E_UNSUPPORTED;
    *position = record_end;
    return WB_OK;
}

int wb_zip_next(wb_zip *z, unsigned *cursor, wb_zip_entry *e) {
    if (!z || !cursor || !e) return WB_E_ARG;
    if (*cursor >= z->count) return 1;
    uint64_t position = z->cd_off;
    for (unsigned i = 0; i <= *cursor; i++) {
        const int rc = read_central_entry(z, &position, e);
        if (rc != WB_OK) return rc;
    }
    ++*cursor;
    return WB_OK;
}

int wb_zip_find(wb_zip *z, const char *name, wb_zip_entry *e) {
    if (!z || !name || !e) return WB_E_ARG;
    uint64_t position = z->cd_off;
    for (unsigned i = 0; i < z->count; i++) {
        const int rc = read_central_entry(z, &position, e);
        if (rc != WB_OK) return rc;
        if (strcmp(e->name, name) == 0) return WB_OK;
    }
    return WB_E_FORMAT;
}

static int local_data_offset(wb_zip *z, const wb_zip_entry *e, uint64_t *off) {
    uint8_t hdr[30];
    if (e->lho > z->cd_off || z->cd_off - e->lho < sizeof hdr) return WB_E_FORMAT;
    int rc = z->rd.read_at(z->rd.ctx, e->lho, hdr, sizeof hdr);
    if (rc != WB_OK) return rc;
    if (le32(hdr) != SIG_LOCAL || le16(hdr + 6) != e->flags ||
        le16(hdr + 8) != e->method) return WB_E_FORMAT;
    if (!(e->flags & 0x0008u) &&
        (le32(hdr + 14) != e->crc || le32(hdr + 18) != e->csize ||
         le32(hdr + 22) != e->usize)) return WB_E_FORMAT;
    const unsigned namelen = le16(hdr + 26);
    const unsigned extralen = le16(hdr + 28);
    if (!namelen || namelen > WB_ZIP_NAME_MAX || namelen != strlen(e->name))
        return WB_E_FORMAT;
    *off = e->lho + sizeof hdr + namelen + extralen;
    if (*off > z->cd_off || e->csize > z->cd_off - *off) return WB_E_FORMAT;
    char local_name[WB_ZIP_NAME_MAX];
    rc = z->rd.read_at(z->rd.ctx, e->lho + sizeof hdr, local_name, namelen);
    if (rc != WB_OK) return rc;
    return memcmp(local_name, e->name, namelen) == 0 ? WB_OK : WB_E_FORMAT;
}

int wb_zip_read(wb_zip *z, const wb_zip_entry *e, uint8_t *out, size_t cap, size_t *n) {
    if (!z || !e || !out) return WB_E_ARG;
    if (e->usize > cap) return WB_E_LIMIT;
    uint64_t off = 0;
    int rc = local_data_offset(z, e, &off);
    if (rc != WB_OK) return rc;
    if (e->csize > WB_ZIP_MAX_COMPRESSED) return WB_E_LIMIT;
    uint8_t *raw = (uint8_t *)malloc((size_t)e->csize + 1u);
    if (!raw) return WB_E_NOMEM;
    rc = z->rd.read_at(z->rd.ctx, off, raw, (size_t)e->csize);
    if (rc != WB_OK) { free(raw); return rc; }
    size_t produced = 0;
    if (e->method == 0) {
        if (e->csize != e->usize) rc = WB_E_FORMAT;
        else { memcpy(out, raw, (size_t)e->csize); produced = (size_t)e->csize; }
    } else {
        rc = wb_inflate_raw(out, cap, &produced, raw, (size_t)e->csize);
    }
    free(raw);
    if (rc != WB_OK) return rc;
    if (produced != e->usize) return WB_E_FORMAT;
    if (wb_crc32(out, produced) != e->crc) return WB_E_FORMAT;
    if (n) *n = produced;
    return WB_OK;
}

static int write_entry(wb_zip *z, const wb_zip_entry *e, const wb_writer *w, uint64_t *written) {
    uint64_t off = 0;
    int rc = local_data_offset(z, e, &off);
    if (rc != WB_OK) return rc;
    if (e->usize > WB_ZIP_MAX_FILE || e->csize > WB_ZIP_MAX_COMPRESSED)
        return WB_E_LIMIT;
    if (e->csize == 0 && e->usize == 0) {
        if (e->method != 0 || e->crc != 0) return WB_E_FORMAT;
        rc = w->create(w->ctx, e->name, 0);
        if (rc != WB_OK) return rc;
        return w->close(w->ctx);
    }
    uint8_t *raw = (uint8_t *)malloc((size_t)e->csize + 1u);
    if (!raw) return WB_E_NOMEM;
    rc = z->rd.read_at(z->rd.ctx, off, raw, (size_t)e->csize);
    if (rc != WB_OK) { free(raw); return rc; }
    uint8_t *data = NULL;
    size_t len = (size_t)e->usize;
    if (e->method == 0) {
        data = raw;
        if (e->csize != e->usize) rc = WB_E_FORMAT;
    } else {
        data = (uint8_t *)malloc(len ? len : 1u);
        if (!data) rc = WB_E_NOMEM;
        else {
            size_t produced = 0;
            rc = wb_inflate_raw(data, len, &produced, raw, (size_t)e->csize);
            if (rc == WB_OK && produced != len) rc = WB_E_FORMAT;
        }
    }
    if (rc == WB_OK && wb_crc32(data, len) != e->crc) rc = WB_E_FORMAT;
    if (rc == WB_OK) {
        rc = w->create(w->ctx, e->name, (uint64_t)len);
        if (rc == WB_OK) {
            if (len) rc = w->write(w->ctx, data, len);
            const int close_rc = w->close(w->ctx);
            if (rc == WB_OK) rc = close_rc;
        }
    }
    if (data != raw) free(data);
    free(raw);
    if (rc == WB_OK && written) *written += (uint64_t)len;
    return rc;
}

static int compare_names(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int validate_entries(wb_zip *z) {
    if (!z->count) return z->cd_size ? WB_E_FORMAT : WB_OK;
    char (*names)[WB_ZIP_NAME_MAX + 1] = calloc(z->count, sizeof *names);
    if (!names) return WB_E_NOMEM;

    uint64_t position = z->cd_off;
    uint64_t total = 0;
    int rc = WB_OK;
    for (unsigned i = 0; i < z->count; i++) {
        wb_zip_entry e;
        rc = read_central_entry(z, &position, &e);
        if (rc != WB_OK) break;
        if (!wb_zip_name_ok(e.name)) { rc = WB_E_PATH; break; }

        size_t len = strlen(e.name);
        if (e.name[len - 1] == '/') {
            if (e.usize != 0) { rc = WB_E_FORMAT; break; }
            len--;
        }
        for (size_t j = 0; j < len; j++) {
            const char c = e.name[j];
            names[i][j] = c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
        }

        if (e.usize > WB_ZIP_MAX_FILE || e.csize > WB_ZIP_MAX_COMPRESSED ||
            e.usize > WB_ZIP_MAX_TOTAL - total) { rc = WB_E_LIMIT; break; }
        total += e.usize;
        uint64_t offset;
        rc = local_data_offset(z, &e, &offset);
        if (rc != WB_OK) break;
    }

    if (rc == WB_OK && position != z->cd_off + z->cd_size) rc = WB_E_FORMAT;
    if (rc == WB_OK) {
        qsort(names, z->count, sizeof *names, compare_names);
        for (unsigned i = 1; i < z->count; i++) {
            if (!strcmp(names[i - 1], names[i])) { rc = WB_E_FORMAT; break; }
        }
    }
    free(names);
    return rc;
}

int wb_zip_extract_all(wb_zip *z, const wb_writer *w, wb_zip_stats *st,
                       wb_zip_progress cb, void *ctx) {
    if (!z || !w || !w->create || !w->write || !w->close || !w->mkdirs) return WB_E_ARG;
    wb_zip_stats local;
    memset(&local, 0, sizeof local);
    if (st) *st = local;
    const int validation = validate_entries(z);
    if (validation != WB_OK) return validation;
    uint64_t position = z->cd_off;
    for (unsigned i = 0; i < z->count; i++) {
        wb_zip_entry e;
        const int nrc = read_central_entry(z, &position, &e);
        if (nrc != WB_OK) { if (st) *st = local; return nrc; }
        if (!wb_zip_name_ok(e.name)) { if (st) *st = local; return WB_E_PATH; }
        if (e.usize > WB_ZIP_MAX_TOTAL - local.bytes) { if (st) *st = local; return WB_E_LIMIT; }
        const bool dir = e.name[strlen(e.name) - 1] == '/';
        int rc;
        if (dir) {
            rc = w->mkdirs(w->ctx, e.name);
            if (rc == WB_OK) local.dirs++;
        } else {
            rc = write_entry(z, &e, w, &local.bytes);
            if (rc == WB_OK) local.files++;
        }
        if (rc != WB_OK) { if (st) *st = local; return rc; }
        if (cb) cb(ctx, &local, e.name);
    }
    if (st) *st = local;
    return WB_OK;
}
