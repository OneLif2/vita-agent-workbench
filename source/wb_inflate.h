#ifndef WB_INFLATE_H
#define WB_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/* Raw RFC 1951 decoder. Callbacks transfer exactly n bytes or return a WB error.
 * Memory is bounded by a 32KiB history and two 16KiB I/O buffers, independent
 * of compressed / expanded lengths. Output may be partial on any error.
 * Input is an exact DEFLATE stream; trailing compressed bytes are rejected. */
typedef int (*wb_inflate_read_fn)(const void *ctx, uint64_t off, void *buf, size_t n);
typedef int (*wb_inflate_write_fn)(void *ctx, const void *buf, size_t n);
int wb_inflate_stream(wb_inflate_read_fn read_at, const void *read_ctx, uint64_t inlen,
                      wb_inflate_write_fn write, void *write_ctx, uint64_t outcap,
                      uint64_t *outlen);

/* Compatibility adapter: the caller owns the whole output buffer. */
int wb_inflate_raw(uint8_t *out, size_t outcap, size_t *outlen,
                   const uint8_t *in, size_t inlen);

#endif
