#ifndef WB_SHA1_H
#define WB_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[5];
    uint64_t total;
    uint8_t  buf[64];
    size_t   fill;
} wb_sha1;

void wb_sha1_init(wb_sha1 *c);
void wb_sha1_update(wb_sha1 *c, const void *data, size_t len);
void wb_sha1_final(wb_sha1 *c, uint8_t out[20]);

#endif
