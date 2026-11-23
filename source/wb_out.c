#include "wb_out.h"
#include "wb_err.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int wb_out_puts(wb_out *o, const char *s) {
    if (!o || !o->write || !s) return WB_E_ARG;
    return o->write(o->ctx, s, strlen(s));
}

int wb_out_printf(wb_out *o, const char *fmt, ...) {
    if (!o || !o->write || !fmt) return WB_E_ARG;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n <= 0) return WB_E_FORMAT;
    if ((size_t)n >= sizeof buf) return o->write(o->ctx, buf, sizeof buf - 1);
    return o->write(o->ctx, buf, (size_t)n);
}
