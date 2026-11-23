#include "wb_inflate.h"
#include "wb_err.h"

typedef struct {
    const uint8_t *in;
    size_t inlen;
    size_t inpos;
    uint32_t bitbuf;
    unsigned bitcnt;
    uint8_t *out;
    size_t outcap;
    size_t outlen;
    int err;
} state;

typedef struct {
    short count[16];
    short symbol[320];
} huff;

static int need(state *s, unsigned n) {
    while (s->bitcnt < n) {
        if (s->inpos >= s->inlen) { s->err = WB_E_PARTIAL; return 0; }
        s->bitbuf |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    return 1;
}

static unsigned getbits(state *s, unsigned n) {
    if (!need(s, n)) return 0;
    const uint32_t mask = (n == 32) ? 0xffffffffu : ((1u << n) - 1u);
    const unsigned v = (unsigned)(s->bitbuf & mask);
    s->bitbuf >>= n;
    s->bitcnt -= n;
    return v;
}

static void huff_build(huff *h, const unsigned char *length, int n) {
    int i;
    for (i = 0; i < 16; i++) h->count[i] = 0;
    for (i = 0; i < n; i++) h->count[length[i]]++;
    h->count[0] = 0;
    short offs[16];
    offs[0] = 0;
    offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = (short)(offs[i] + h->count[i]);
    for (i = 0; i < n; i++)
        if (length[i]) h->symbol[offs[length[i]]++] = (short)i;
}

static int huff_decode(state *s, const huff *h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; len++) {
        if (!need(s, 1)) return -1;
        code |= (int)getbits(s, 1);
        const int count = h->count[len];
        if (code - first < count) return h->symbol[index + (code - first)];
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

static int put_byte(state *s, uint8_t v) {
    if (s->outlen >= s->outcap) { s->err = WB_E_LIMIT; return 0; }
    s->out[s->outlen++] = v;
    return 1;
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
        const size_t d = (size_t)DBASE[dsym] + getbits(s, (unsigned)DEXT[dsym]);
        if (d > s->outlen) { s->err = WB_E_FORMAT; return 0; }
        for (unsigned i = 0; i < len; i++)
            if (!put_byte(s, s->out[s->outlen - d])) return 0;
        if (s->err) return 0;
    }
}

static int stored(state *s) {
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->inpos + 4 > s->inlen) { s->err = WB_E_PARTIAL; return 0; }
    const unsigned len = (unsigned)s->in[s->inpos] | ((unsigned)s->in[s->inpos + 1] << 8);
    const unsigned nlen = (unsigned)s->in[s->inpos + 2] | ((unsigned)s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if ((len ^ 0xffffu) != nlen) { s->err = WB_E_FORMAT; return 0; }
    if (s->inpos + len > s->inlen) { s->err = WB_E_PARTIAL; return 0; }
    if (s->outlen + len > s->outcap) { s->err = WB_E_LIMIT; return 0; }
    for (unsigned i = 0; i < len; i++) s->out[s->outlen++] = s->in[s->inpos++];
    return 1;
}

static int fixed_blocks(state *s) {
    huff lit, dist;
    unsigned char lengths[288];
    for (int i = 0; i < 288; i++) lengths[i] = (unsigned char)(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
    huff_build(&lit, lengths, 288);
    for (int i = 0; i < 30; i++) lengths[i] = 5;
    huff_build(&dist, lengths, 30);
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
    if (nlen > 286 || ndist > 30) { s->err = WB_E_FORMAT; return 0; }

    for (int i = 0; i < 19; i++) lengths[i] = 0;
    for (int i = 0; i < ncode; i++) {
        lengths[order[i]] = (unsigned char)getbits(s, 3);
        if (s->err) return 0;
    }
    huff_build(&lencode, lengths, 19);

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

    huff_build(&lencode, lengths, nlen);
    huff_build(&distcode, lengths + nlen, ndist);
    return codes(s, &lencode, &distcode);
}

int wb_inflate_raw(uint8_t *out, size_t outcap, size_t *outlen,
                   const uint8_t *in, size_t inlen) {
    state s;
    s.in = in; s.inlen = inlen; s.inpos = 0;
    s.bitbuf = 0; s.bitcnt = 0;
    s.out = out; s.outcap = outcap; s.outlen = 0;
    s.err = WB_OK;
    int last = 0;
    while (!last) {
        last = (int)getbits(&s, 1);
        const unsigned type = getbits(&s, 2);
        if (s.err) break;
        int ok;
        if (type == 0)      ok = stored(&s);
        else if (type == 1) ok = fixed_blocks(&s);
        else if (type == 2) ok = dynamic_blocks(&s);
        else { s.err = WB_E_FORMAT; ok = 0; }
        if (!ok) break;
    }
    if (outlen) *outlen = s.outlen;
    return s.err ? s.err : WB_OK;
}
