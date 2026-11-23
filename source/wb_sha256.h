#ifndef WB_SHA256_H
#define WB_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   fill;
} wb_sha256;

void wb_sha256_init(wb_sha256 *c);
void wb_sha256_update(wb_sha256 *c, const void *data, size_t len);
void wb_sha256_final(wb_sha256 *c, uint8_t out[32]);
void wb_sha_hex(const uint8_t *in, size_t n, char out[65]);

#endif
