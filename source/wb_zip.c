#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("O3")
#endif
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

#ifdef __vita__
#define ZIP_IO_SIZE 131072u
#else
#define ZIP_IO_SIZE 16384u
#endif

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
        if (i >= 20u && le32(tail + i - 20u) == 0x07064b50u) {
            found = WB_E_ZIP64; break; /* ZIP64 EOCD locator */
        }
        /* ZIP64 uses these marker values even when a ZIP64 extra is absent.
         * Do not silently reinterpret them as a supported ZIP32 archive. */
        if (entries == 0xffffu || csize == UINT32_MAX || coff == UINT32_MAX) {
            found = WB_E_ZIP64; break;
        }
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
    z->next_off = z->cd_off;
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
    if (e->usize == UINT32_MAX || e->csize == UINT32_MAX || e->lho == UINT32_MAX)
        return WB_E_ZIP64; /* ZIP64 is not implemented. */
    /* ZIP64 extra fields are rejected even when small compatibility fields fit. */
    uint64_t extra_pos = pos + sizeof hdr + namelen;
    const uint64_t extra_end = extra_pos + extralen;
    while (extra_pos < extra_end) {
        uint8_t extra[4];
        if (extra_end - extra_pos < sizeof extra) return WB_E_FORMAT;
        rc = z->rd.read_at(z->rd.ctx, extra_pos, extra, sizeof extra);
        if (rc != WB_OK) return rc;
        const unsigned id = le16(extra), size = le16(extra + 2);
        extra_pos += sizeof extra;
        if (size > extra_end - extra_pos) return WB_E_FORMAT;
        if (id == 0x0001u) return WB_E_ZIP64;
        extra_pos += size;
    }
    if (e->flags & (0x0001u | 0x0040u | 0x2000u)) return WB_E_UNSUPPORTED; /* encrypted */
    /* Never materialise Unix links, devices or sockets as package files. */
    const unsigned mode = le32(hdr + 38) >> 16;
    const unsigned kind = mode & 0170000u;
    if (kind && kind != 0100000u && kind != 0040000u) return WB_E_UNSUPPORTED;
    if ((kind == 0040000u) != (e->name[namelen - 1] == '/') && kind)
        return WB_E_FORMAT;
    if (e->method != 0 && e->method != 8) return WB_E_UNSUPPORTED;
    *position = record_end;
    return WB_OK;
}

int wb_zip_next(wb_zip *z, unsigned *cursor, wb_zip_entry *e) {
    if (!z || !cursor || !e) return WB_E_ARG;
    if (*cursor >= z->count) return 1;
    uint64_t position = z->cd_off;
    unsigned start = 0;
    if (*cursor == z->next_index) { position = z->next_off; start = *cursor; }
    for (unsigned i = start; i <= *cursor; i++) {
        const int rc = read_central_entry(z, &position, e);
        if (rc != WB_OK) return rc;
    }
    ++*cursor;
    z->next_index = *cursor; z->next_off = position;
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
    if (le32(hdr + 18) == UINT32_MAX || le32(hdr + 22) == UINT32_MAX) return WB_E_ZIP64;
    if (!(e->flags & 0x0008u) &&
        (le32(hdr + 14) != e->crc || le32(hdr + 18) != e->csize ||
         le32(hdr + 22) != e->usize)) return WB_E_FORMAT;
    const unsigned namelen = le16(hdr + 26);
    const unsigned extralen = le16(hdr + 28);
    if (!namelen || namelen > WB_ZIP_NAME_MAX || namelen != strlen(e->name))
        return WB_E_FORMAT;
    *off = e->lho + sizeof hdr + namelen + extralen;
    if (*off > z->cd_off || e->csize > z->cd_off - *off) return WB_E_FORMAT;
    if (e->flags & 0x0008u) {
        /* Descriptor CRC / sizes must agree with central metadata. */
        if ((le32(hdr + 14) && le32(hdr + 14) != e->crc) ||
            (le32(hdr + 18) && le32(hdr + 18) != e->csize) ||
            (le32(hdr + 22) && le32(hdr + 22) != e->usize)) return WB_E_FORMAT;
        uint8_t desc[16];
        const uint64_t pos = *off + e->csize;
        if (pos > z->cd_off || z->cd_off - pos < 12u) return WB_E_FORMAT;
        rc = z->rd.read_at(z->rd.ctx, pos, desc, 12);
        if (rc != WB_OK) return rc;
        /* A signature-free CRC is allowed to equal the optional signature. */
        if (le32(desc) != e->crc || le32(desc + 4u) != e->csize ||
            le32(desc + 8u) != e->usize) {
            if (le32(desc) != 0x08074b50u || z->cd_off - pos < 16u) return WB_E_FORMAT;
            rc = z->rd.read_at(z->rd.ctx, pos + 12u, desc + 12u, 4);
            if (rc != WB_OK) return rc;
            if (le32(desc + 4u) != e->crc || le32(desc + 8u) != e->csize ||
                le32(desc + 12u) != e->usize) return WB_E_FORMAT;
        }
    }
    char local_name[WB_ZIP_NAME_MAX];
    rc = z->rd.read_at(z->rd.ctx, e->lho + sizeof hdr, local_name, namelen);
    if (rc != WB_OK) return rc;
    return memcmp(local_name, e->name, namelen) == 0 ? WB_OK : WB_E_FORMAT;
}

typedef struct {
    wb_zip *zip;
    uint64_t offset, size, produced;
    uint32_t crc;
    wb_zip_sink sink;
    void *sink_ctx;
} stream_ctx;

static int stream_read(const void *ctx, uint64_t off, void *buf, size_t n) {
    const stream_ctx *c = (const stream_ctx *)ctx;
    if (off > c->size || n > c->size - off) return WB_E_PARTIAL;
    return c->zip->rd.read_at(c->zip->rd.ctx, c->offset + off, buf, n);
}
static int stream_write(void *ctx, const void *buf, size_t n) {
    stream_ctx *c = (stream_ctx *)ctx;
    const int rc = c->sink(c->sink_ctx, buf, n);
    if (rc != WB_OK) return rc;
    c->crc = wb_crc32_update(c->crc, buf, n);
    c->produced += n;
    return WB_OK;
}

int wb_zip_stream_entry(wb_zip *z, const wb_zip_entry *e, wb_zip_sink sink,
                         void *ctx, uint64_t *n) {
    if (n) *n = 0;
    if (!z || !e || !sink) return WB_E_ARG;
    if (!wb_zip_name_ok(e->name)) return WB_E_PATH;
    if (e->method != 0 && e->method != 8) return WB_E_UNSUPPORTED;
    if (e->flags & (0x0001u | 0x0040u | 0x2000u)) return WB_E_UNSUPPORTED;
    stream_ctx c = {.zip=z, .size=e->csize, .sink=sink, .sink_ctx=ctx};
    int rc = local_data_offset(z, e, &c.offset);
    if (rc != WB_OK) return rc;
    if (e->method == 0) {
        if (e->csize != e->usize) return WB_E_FORMAT;
#ifdef __vita__
        uint8_t fallback[16384];
        uint8_t *heap = (uint8_t *)malloc(ZIP_IO_SIZE);
        uint8_t *buf = heap ? heap : fallback;
        const size_t cap = heap ? ZIP_IO_SIZE : sizeof fallback;
#else
        uint8_t buf[ZIP_IO_SIZE];
        const size_t cap = sizeof buf;
#endif
        uint64_t pos = 0;
        while (pos < e->csize) {
            const uint64_t left = e->csize - pos;
            const size_t len = left > cap ? cap : (size_t)left;
            rc = stream_read(&c, pos, buf, len);
            if (rc != WB_OK) break;
            rc = stream_write(&c, buf, len);
            if (rc != WB_OK) break;
            pos += len;
        }
#ifdef __vita__
        free(heap);
#endif
    } else {
        uint64_t produced = 0;
        rc = wb_inflate_stream(stream_read, &c, e->csize, stream_write, &c,
                               e->usize, &produced);
    }
    if (n) *n = c.produced;
    if (rc != WB_OK) return rc;
    if (c.produced != e->usize || c.crc != e->crc) return WB_E_FORMAT;
    return WB_OK;
}

typedef struct { uint8_t *out; size_t pos, cap; } buffer_sink;
static int buffer_write(void *ctx, const void *buf, size_t n) {
    buffer_sink *b = (buffer_sink *)ctx;
    if (n > b->cap - b->pos) return WB_E_LIMIT;
    memcpy(b->out + b->pos, buf, n); b->pos += n;
    return WB_OK;
}
int wb_zip_read(wb_zip *z, const wb_zip_entry *e, uint8_t *out, size_t cap, size_t *n) {
    if (n) *n = 0;
    if (!z || !e || (!out && e->usize)) return WB_E_ARG;
    if (e->usize > cap) return WB_E_LIMIT;
    buffer_sink b = {out, 0, cap};
    uint64_t produced = 0;
    const int rc = wb_zip_stream_entry(z, e, buffer_write, &b, &produced);
    if (n) *n = b.pos;
    return rc;
}

static int writer_sink(void *ctx, const void *buf, size_t n) {
    const wb_writer *w = (const wb_writer *)ctx;
    return w->write(w->ctx, buf, n);
}
static int write_entry(wb_zip *z, const wb_zip_entry *e, const wb_writer *w, uint64_t *written) {
    int rc = w->create(w->ctx, e->name, e->usize);
    if (rc != WB_OK) return rc;
    uint64_t produced = 0;
    rc = wb_zip_stream_entry(z, e, writer_sink, (void *)w, &produced);
    const int close_rc = w->close(w->ctx); /* also close on CRC/read/write failure */
    if (rc == WB_OK) rc = close_rc;
    if (rc == WB_OK && written) *written += produced;
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

        if (e.usize > UINT64_MAX - total) { rc = WB_E_LIMIT; break; }
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
        if (e.usize > UINT64_MAX - local.bytes) { if (st) *st = local; return WB_E_LIMIT; }
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
