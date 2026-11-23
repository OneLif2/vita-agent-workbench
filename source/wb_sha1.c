#include "wb_sha1.h"

#include <string.h>

static uint32_t rol(uint32_t x, unsigned n) { return (x << n) | (x >> (32u - n)); }

static void compress(uint32_t h[5], const uint8_t blk[64]) {
    uint32_t w[80];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    }
    for (unsigned i = 16; i < 80; i++) {
        const uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = rol(v, 1);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (unsigned i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);      k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d;                  k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else             { f = b ^ c ^ d;                  k = 0xca62c1d6u; }
        const uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void wb_sha1_init(wb_sha1 *c) {
    c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u; c->h[2] = 0x98badcfeu;
    c->h[3] = 0x10325476u; c->h[4] = 0xc3d2e1f0u;
    c->total = 0;
    c->fill = 0;
}

void wb_sha1_update(wb_sha1 *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    c->total += (uint64_t)len;
    while (len) {
        const size_t room = 64 - c->fill;
        const size_t take = len < room ? len : room;
        memcpy(c->buf + c->fill, p, take);
        c->fill += take; p += take; len -= take;
        if (c->fill == 64) { compress(c->h, c->buf); c->fill = 0; }
    }
}

void wb_sha1_final(wb_sha1 *c, uint8_t out[20]) {
    const uint64_t bits = c->total * 8u;
    uint8_t pad = 0x80;
    wb_sha1_update(c, &pad, 1);
    pad = 0;
    while (c->fill != 56) wb_sha1_update(c, &pad, 1);
    uint8_t len_be[8];
    for (unsigned i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56u - 8u * i));
    c->total -= 8;
    wb_sha1_update(c, len_be, 8);
    for (unsigned i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
}
