#ifndef WB_OUT_H
#define WB_OUT_H

#include <stddef.h>

/* Line oriented sink: SSH channel on the device, memory buffer in tests. */
typedef struct wb_out {
    void *ctx;
    int (*write)(void *ctx, const char *buf, size_t n);
} wb_out;

int wb_out_puts(wb_out *o, const char *s);
int wb_out_printf(wb_out *o, const char *fmt, ...);

#endif
