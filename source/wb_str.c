#include "wb_str.h"

bool wb_parse_u64(const char *s, uint64_t *out) {
    uint64_t v = 0;
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        const unsigned d = (unsigned)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u) return false;
        v = v * 10u + d;
    }
    if (out) *out = v;
    return true;
}

static int nib(unsigned c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

int wb_hex_decode(const char *hex, uint8_t *out, size_t cap) {
    if (!hex) return -1;
    size_t n = 0;
    while (hex[n * 2] && hex[n * 2 + 1]) {
        const int hi = nib((unsigned char)hex[n * 2]);
        const int lo = nib((unsigned char)hex[n * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= cap) return -1;
        out[n] = (uint8_t)((hi << 4) | lo);
        n++;
    }
    if (hex[n * 2]) return -1; /* odd number of digits */
    return (int)n;
}

static bool ver_split(const char *s, unsigned *part, unsigned *count) {
    unsigned n = 0;
    const char *p = s;
    if (!s || !*s) return false;
    while (1) {
        unsigned v = 0, digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (digits == 4) return false;
            v = v * 10u + (unsigned)(*p - '0');
            digits++; p++;
        }
        if (digits == 0 || n >= 4) return false;
        part[n++] = v;
        if (*p == 0) break;
        if (*p != '.') return false;
        p++;
    }
    *count = n;
    return true;
}

int wb_ver_cmp(const char *a, const char *b) {
    unsigned pa[4] = {0}, pb[4] = {0}, na = 0, nb = 0;
    if (!ver_split(a, pa, &na) || !ver_split(b, pb, &nb)) return 0x7fffffff;
    for (unsigned i = 0; i < 4; i++) {
        if (pa[i] < pb[i]) return -1;
        if (pa[i] > pb[i]) return 1;
    }
    return 0;
}

size_t wb_strcpy(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return 0;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
    }
    dst[i] = 0;
    return i;
}

static int lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

int wb_icmp(const char *a, const char *b) {
    if (!a || !b) return a == b ? 0 : (a ? 1 : -1);
    while (*a && lower((unsigned char)*a) == lower((unsigned char)*b)) { a++; b++; }
    return lower((unsigned char)*a) - lower((unsigned char)*b);
}
