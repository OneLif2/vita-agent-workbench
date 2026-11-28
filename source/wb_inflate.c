#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("O3")
#endif
#include "wb_inflate.h"
#include "wb_err.h"

#include <stdlib.h>
#include <string.h>

#ifdef __vita__
#define IO_SIZE 131072u
#else
#define IO_SIZE 16384u
#endif
#define WINDOW_SIZE 32768u
#define FAST_BITS 9u
#define FAST_SIZE (1u << FAST_BITS)
#define FAST_MASK (FAST_SIZE - 1u)

typedef struct {
    wb_inflate_read_fn read_at;
    const void *read_ctx;
    wb_inflate_write_fn write;
    void *write_ctx;
    uint64_t inlen, inpos, outcap, outlen;
    uint8_t input[IO_SIZE], output[IO_SIZE], window[WINDOW_SIZE];
    size_t input_pos, input_len, output_len;
    uint32_t bitbuf;
    unsigned bitcnt;
    int err;
} state;

typedef struct {
    short count[16];
    short symbol[320];
    uint16_t fast[FAST_SIZE]; /* (len << 10) | sym, 0 = slow path */
} huff;

static inline int input_refill(state *s) {
    uint64_t left = s->inlen - s->inpos;
    if (!left) { s->err = WB_E_PARTIAL; return -1; }
    size_t n = left > IO_SIZE ? IO_SIZE : (size_t)left;
    s->err = s->read_at(s->read_ctx, s->inpos, s->input, n);
    if (s->err) return -1;
    s->input_pos = 0;
    s->input_len = n;
    return 0;
}

static inline int input_byte(state *s) {
    if (s->input_pos == s->input_len && input_refill(s) < 0) return -1;
    s->inpos++;
    return s->input[s->input_pos++];
}

static inline void fill_fast(state *s) {
    while (s->bitcnt <= 24u) {
        if (s->input_pos == s->input_len) {
            if (s->inpos >= s->inlen) break;
            if (input_refill(s) < 0) break;
        }
        s->bitbuf |= (uint32_t)s->input[s->input_pos++] << s->bitcnt;
        s->inpos++;
        s->bitcnt += 8u;
    }
}

static inline int need(state *s, unsigned n) {
    while (s->bitcnt < n) {
        int c = input_byte(s);
        if (c < 0) return 0;
        s->bitbuf |= (uint32_t)c << s->bitcnt;
        s->bitcnt += 8;
    }
    return 1;
}

static inline unsigned getbits(state *s, unsigned n) {
    if (!n) return 0;
    if (s->bitcnt < n && !need(s, n)) return 0;
    const uint32_t mask = (n == 32) ? 0xffffffffu : ((1u << n) - 1u);
    const unsigned v = (unsigned)(s->bitbuf & mask);
    s->bitbuf >>= n;
    s->bitcnt -= n;
    return v;
}

static unsigned bit_rev(unsigned code, int len) {
    unsigned r = 0;
    for (int i = 0; i < len; i++) {
        r = (r << 1) | (code & 1u);
        code >>= 1;
    }
    return r;
}

static int huff_build(huff *h, const unsigned char *length, int n, int require_complete) {
    int i;
    for (i = 0; i < 16; i++) h->count[i] = 0;
    for (i = 0; i < n; i++) h->count[length[i]]++;
    h->count[0] = 0;
    int left = 1, max = 0;
    for (i = 1; i < 16; i++) {
        left = (left << 1) - h->count[i];
        if (left < 0) return 0; /* oversubscribed */
        if (h->count[i]) max = i;
    }
    if (left && (require_complete || max > 1)) return 0;
    short offs[16];
    offs[0] = 0;
    offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = (short)(offs[i] + h->count[i]);
    for (i = 0; i < n; i++)
        if (length[i]) h->symbol[offs[length[i]]++] = (short)i;
    /* Populate 9-bit bit-reversed fast lookup table for O(1) common-symbol decode. */
    memset(h->fast, 0, sizeof h->fast);
    unsigned code = 0;
    int idx = 0;
    for (int len = 1; len <= (int)FAST_BITS; len++) {
        const int cnt = h->count[len];
        const unsigned step = 1u << len;
        for (int k = 0; k < cnt; k++, code++, idx++) {
            const uint16_t entry = (uint16_t)(((unsigned)len << 10) | (unsigned)h->symbol[idx]);
            for (unsigned rev = bit_rev(code, len); rev < FAST_SIZE; rev += step)
                h->fast[rev] = entry;
        }
        code <<= 1;
    }
    return 1;
}

static inline int huff_decode(state *s, const huff *h) {
    if (s->bitcnt < FAST_BITS) fill_fast(s);
    if (s->err) return -1;
    const uint16_t e = h->fast[s->bitbuf & FAST_MASK];
    const unsigned elen = (unsigned)(e >> 10);
    if (elen && elen <= s->bitcnt) {
        s->bitbuf >>= elen;
        s->bitcnt -= elen;
        return (int)(e & 1023u);
    }
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; len++) {
        if (!need(s, 1)) return -1;
        code |= (int)(s->bitbuf & 1u);
        s->bitbuf >>= 1;
        s->bitcnt--;
        const int count = h->count[len];
        if (code >= first && code - first < count) return h->symbol[index + (code - first)];
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    s->err = WB_E_FORMAT;
    return -1;
}

static const short LBASE[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
                                67,83,99,115,131,163,195,227,258};
static const short LEXT[29]  = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const short DBASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
                                1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const short DEXT[30]  = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static int flush_output(state *s) {
    if (!s->output_len) return 1;
    s->err = s->write(s->write_ctx, s->output, s->output_len);
    if (s->err) return 0;
    s->output_len = 0;
    return 1;
}

static int put_byte(state *s, uint8_t v) {
    if (s->outlen >= s->outcap) { s->err = WB_E_LIMIT; return 0; }
    s->window[(size_t)(s->outlen & (WINDOW_SIZE - 1u))] = v;
    s->outlen++;
    s->output[s->output_len++] = v;
    return s->output_len < IO_SIZE || flush_output(s);
}

static int codes(state *s, const huff *lit, const huff *dist) {
    for (;;) {
        int sym = huff_decode(s, lit);
        if (sym < 0) return 0;
        if (sym < 256) {
            if (!put_byte(s, (uint8_t)sym)) return 0;
            continue;
        }
        if (sym == 256) return 1;
        sym -= 257;
        if (sym >= 29) { s->err = WB_E_FORMAT; return 0; }
        const unsigned len = (unsigned)LBASE[sym] + getbits(s, (unsigned)LEXT[sym]);
        int dsym = huff_decode(s, dist);
        if (dsym < 0) return 0;
        if (dsym >= 30) { s->err = WB_E_FORMAT; return 0; }
        const unsigned d = (unsigned)DBASE[dsym] + getbits(s, (unsigned)DEXT[dsym]);
        if (s->err) return 0;
        if (d > s->outlen) { s->err = WB_E_FORMAT; return 0; }
        for (unsigned i = 0; i < len; i++)
            if (!put_byte(s, s->window[(size_t)((s->outlen - d) & (WINDOW_SIZE - 1u))])) return 0;
        if (s->err) return 0;
    }
}

static int stored(state *s) {
    const unsigned drop = s->bitcnt & 7u;
    s->bitbuf >>= drop;
    s->bitcnt -= drop;
    unsigned len = getbits(s, 16);
    const unsigned nlen = getbits(s, 16);
    if (s->err) return 0;
    if ((len ^ 0xffffu) != nlen) { s->err = WB_E_FORMAT; return 0; }
    while (len && s->bitcnt >= 8u) {
        if (!put_byte(s, (uint8_t)getbits(s, 8))) return 0;
        len--;
    }
    for (unsigned i = 0; i < len; i++) {
        int c = input_byte(s);
        if (c < 0 || !put_byte(s, (uint8_t)c)) return 0;
    }
    return 1;
}

static int fixed_blocks(state *s) {
    huff lit, dist;
    unsigned char lengths[288];
    for (int i = 0; i < 288; i++) lengths[i] = (unsigned char)(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
    if (!huff_build(&lit, lengths, 288, 1)) { s->err = WB_E_FORMAT; return 0; }
    for (int i = 0; i < 32; i++) lengths[i] = 5;
    if (!huff_build(&dist, lengths, 32, 1)) { s->err = WB_E_FORMAT; return 0; }
    return codes(s, &lit, &dist);
}

static int dynamic_blocks(state *s) {
    static const unsigned char order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    unsigned char lengths[320];
    huff lencode, distcode;

    const int nlen = (int)getbits(s, 5) + 257;
    const int ndist = (int)getbits(s, 5) + 1;
    const int ncode = (int)getbits(s, 4) + 4;
    if (s->err) return 0;
    if (nlen > 286 || ndist > 32) { s->err = WB_E_FORMAT; return 0; }

    for (int i = 0; i < 19; i++) lengths[i] = 0;
    for (int i = 0; i < ncode; i++) {
        lengths[order[i]] = (unsigned char)getbits(s, 3);
        if (s->err) return 0;
    }
    if (!huff_build(&lencode, lengths, 19, 1)) { s->err = WB_E_FORMAT; return 0; }

    int index = 0;
    while (index < nlen + ndist) {
        int sym = huff_decode(s, &lencode);
        if (sym < 0) return 0;
        if (sym < 16) { lengths[index++] = (unsigned char)sym; continue; }
        unsigned char value = 0;
        int repeat;
        if (sym == 16) {
            if (index == 0) { s->err = WB_E_FORMAT; return 0; }
            value = lengths[index - 1];
            repeat = 3 + (int)getbits(s, 2);
        } else if (sym == 17) {
            repeat = 3 + (int)getbits(s, 3);
        } else {
            repeat = 11 + (int)getbits(s, 7);
        }
        if (s->err) return 0;
        if (index + repeat > nlen + ndist) { s->err = WB_E_FORMAT; return 0; }
        while (repeat--) lengths[index++] = value;
    }
    if (lengths[256] == 0) { s->err = WB_E_FORMAT; return 0; }

    if (!huff_build(&lencode, lengths, nlen, 0) ||
        !huff_build(&distcode, lengths + nlen, ndist, 0)) { s->err = WB_E_FORMAT; return 0; }
    return codes(s, &lencode, &distcode);
}

int wb_inflate_stream(wb_inflate_read_fn read_at, const void *read_ctx, uint64_t inlen,
                      wb_inflate_write_fn write, void *write_ctx, uint64_t outcap,
                      uint64_t *outlen) {
    if (outlen) *outlen = 0;
    if (!read_at || !write) return WB_E_ARG;
    state *s = (state *)calloc(1, sizeof *s);
    if (!s) return WB_E_NOMEM;
    s->read_at = read_at; s->read_ctx = read_ctx; s->inlen = inlen;
    s->write = write; s->write_ctx = write_ctx; s->outcap = outcap;
    int last = 0;
    while (!last) {
        last = (int)getbits(s, 1);
        const unsigned type = getbits(s, 2);
        if (s->err) break;
        int ok;
        if (type == 0)      ok = stored(s);
        else if (type == 1) ok = fixed_blocks(s);
        else if (type == 2) ok = dynamic_blocks(s);
        else { s->err = WB_E_FORMAT; ok = 0; }
        if (!ok) break;
    }
    if (!s->err && (s->inpos != s->inlen || s->bitcnt >= 8u)) s->err = WB_E_FORMAT;
    if (!s->err) (void)flush_output(s);
    if (outlen) *outlen = s->outlen;
    const int rc = s->err;
    free(s);
    return rc;
}

typedef struct { const uint8_t *p; size_t n; } mem_input;
typedef struct { uint8_t *p; size_t pos; } mem_output;
static int mem_read(const void *ctx, uint64_t off, void *buf, size_t n) {
    const mem_input *m = (const mem_input *)ctx;
    if (off > m->n || n > m->n - off) return WB_E_PARTIAL;
    memcpy(buf, m->p + (size_t)off, n);
    return WB_OK;
}
static int mem_write(void *ctx, const void *buf, size_t n) {
    mem_output *m = (mem_output *)ctx;
    memcpy(m->p + m->pos, buf, n); m->pos += n;
    return WB_OK;
}
int wb_inflate_raw(uint8_t *out, size_t outcap, size_t *outlen,
                   const uint8_t *in, size_t inlen) {
    if ((!out && outcap) || (!in && inlen)) return WB_E_ARG;
    const mem_input source = {in, inlen};
    mem_output dest = {out, 0};
    uint64_t produced = 0;
    const int rc = wb_inflate_stream(mem_read, &source, inlen, mem_write, &dest, outcap, &produced);
    if (outlen) *outlen = (size_t)produced;
    return rc;
}
