#ifndef WB_ZIP_H
#define WB_ZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WB_ZIP_NAME_MAX 200
#define WB_ZIP_MAX_ENTRIES 4096u
#define WB_ZIP_MAX_FILE (32u * 1024u * 1024u)
#define WB_ZIP_MAX_TOTAL (256u * 1024u * 1024u)

/* Random access reader. read_at must fill exactly n bytes or fail. */
typedef struct wb_reader {
    const void *ctx;
    uint64_t size;
    int (*read_at)(const void *ctx, uint64_t off, void *buf, size_t n);
} wb_reader;

/* Filesystem sink used while unpacking a package. Every path is relative to
 * the staging root; the implementation is responsible for creating parents. */
typedef struct wb_writer {
    void *ctx;
    int (*mkdirs)(void *ctx, const char *rel);
    int (*create)(void *ctx, const char *rel, uint64_t size);
    int (*write)(void *ctx, const void *buf, size_t n);
    int (*close)(void *ctx);
    int (*remove_tree)(void *ctx, const char *rel);
} wb_writer;

typedef struct {
    char     name[WB_ZIP_NAME_MAX + 1];
    uint16_t method;
    uint16_t flags;
    uint32_t crc;
    uint64_t csize;
    uint64_t usize;
    uint64_t lho;
} wb_zip_entry;

typedef struct {
    wb_reader rd;
    uint64_t cd_off;
    uint64_t cd_size;
    unsigned count;
} wb_zip;

typedef struct {
    unsigned files;
    unsigned dirs;
    uint64_t bytes;
} wb_zip_stats;

typedef void (*wb_zip_progress)(void *ctx, const wb_zip_stats *st, const char *name);

int wb_zip_open(wb_zip *z, const wb_reader *rd);
/* Iterate the central directory. cursor starts at 0; returns 1 at the end. */
int wb_zip_next(wb_zip *z, unsigned *cursor, wb_zip_entry *e);
int wb_zip_find(wb_zip *z, const char *name, wb_zip_entry *e);
/* Read a whole entry into a caller buffer of at least e->usize bytes. */
int wb_zip_read(wb_zip *z, const wb_zip_entry *e, uint8_t *out, size_t cap, size_t *n);
int wb_zip_extract_all(wb_zip *z, const wb_writer *w, wb_zip_stats *st,
                       wb_zip_progress cb, void *ctx);

/* True when a relative archive path may be materialised under the stage root. */
bool wb_zip_name_ok(const char *name);

#endif
