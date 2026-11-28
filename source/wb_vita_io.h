#ifndef WB_VITA_IO_H
#define WB_VITA_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wb_zip.h"

typedef struct { int fd; uint64_t pos; bool pos_valid; } wb_vfile;

typedef struct {
    char root[128];
    int  fd;
} wb_vwriter;

int  wb_vita_reader_open(const char *path, wb_reader *rd, wb_vfile *f);
void wb_vita_reader_close(wb_vfile *f);

int  wb_vita_writer_init(wb_vwriter *w, const char *root);
const wb_writer *wb_vita_writer_ops(wb_vwriter *w);

int  wb_vita_mkdir_p(const char *path);
int  wb_vita_remove_tree(const char *path);
int  wb_vita_copy_file(const char *src, const char *dst);
int  wb_vita_write_file(const char *path, const void *data, size_t n, bool append);
int  wb_vita_read_small(const char *path, void *buf, size_t cap, size_t *n);
bool wb_vita_exists(const char *path);

#endif
