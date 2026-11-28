#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("O3")
#endif
#include "wb_sftp_frame.h"
#include <string.h>
int wb_sf_pump(wb_sftp_frame *f,void *ctx,wb_sf_read rd,wb_sf_write wr) {
#ifdef __vita__
    for (unsigned step=0;step<256;step++) {
        if (f->pending && (f->sent || f->pending >= 2048u || sizeof f->out - f->pending < 4u + WB_SFTP_REPLY_MAX)) {
            size_t rem=f->pending-f->sent;
            int n=wr(ctx,f->out+f->sent,rem);
            if(n==0)return 1;
            if(n<0 || (size_t)n>rem)return -1;
            f->sent+=(size_t)n;
            if(f->sent==f->pending)f->sent=f->pending=0;
            continue;
        }
        size_t have = f->avail - f->pos;
        if (!f->need && have >= 4u) {
            const uint8_t *p = f->in + f->pos;
            uint32_t k = ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) |
                         ((uint32_t)p[2]<<8)  | (uint32_t)p[3];
            if (!k || k > WB_SFTP_PACKET_MAX) return -1;
            f->need = 4u + (size_t)k;
        }
        if (f->need && have >= f->need) {
            size_t k = 0;
            size_t room = sizeof f->out - f->pending;
            if (room < 4u + WB_SFTP_REPLY_MAX) continue;
            if (wb_sftp_reply(&f->engine, f->in + f->pos + 4u, f->need - 4u,
                              f->out + f->pending + 4u, room - 4u, &k) != 0 ||
                !k || k > room - 4u) return -1;
            f->out[f->pending + 0u] = (uint8_t)(k >> 24);
            f->out[f->pending + 1u] = (uint8_t)(k >> 16);
            f->out[f->pending + 2u] = (uint8_t)(k >> 8);
            f->out[f->pending + 3u] = (uint8_t)k;
            f->pending += 4u + k;
            f->pos += f->need;
            f->need = 0;
            if (f->pos == f->avail) f->pos = f->avail = 0;
            f->got = f->avail - f->pos;
            continue;
        }
        if (f->pos > 0 && (f->avail == sizeof f->in || (f->need && sizeof f->in - f->pos < f->need))) {
            if (have) memmove(f->in, f->in + f->pos, have);
            f->avail = have;
            f->pos = 0;
        }
        size_t cap = sizeof f->in - f->avail;
        int n = rd(ctx, f->in + f->avail, cap);
        if (n == 0) {
            if (f->pending) {
                size_t rem = f->pending - f->sent;
                int w = wr(ctx, f->out + f->sent, rem);
                if (w < 0 || (size_t)w > rem) return -1;
                f->sent += (size_t)w;
                if (f->sent == f->pending) f->sent = f->pending = 0;
                if (w > 0 && f->pending) continue;
            }
            return 1;
        }
        if (n == -2) {
            if (f->pending) {
                size_t rem = f->pending - f->sent;
                int w = wr(ctx, f->out + f->sent, rem);
                if (w == 0) return 1;
                if (w < 0 || (size_t)w > rem) return -1;
                f->sent += (size_t)w;
                if (f->sent == f->pending) f->sent = f->pending = 0;
                continue;
            }
            return have == 0 ? 0 : -1;
        }
        if (n < 0 || (size_t)n > cap) return -1;
        f->avail += (size_t)n;
        f->got = f->avail - f->pos;
    }
    return 1;
#else
    for (unsigned step=0;step<128;step++) {
        if(f->pending) {
            size_t rem=f->pending-f->sent;
            int n=wr(ctx,f->out+f->sent,rem);
            if(n==0)return 1;
            if(n<0 || (size_t)n>rem)return -1;
            f->sent+=(size_t)n;
            if(f->sent==f->pending)f->sent=f->pending=0;
            continue;
        }
        size_t rem=(f->need?f->need:4)-f->got;
        int n=rd(ctx,f->in+f->got,rem);
        if(n==0)return 1;
        if(n==-2 && !f->got)return 0;
        if(n<0 || (size_t)n>rem)return -1;
        f->got+=(size_t)n;
        if(!f->need && f->got==4) {
            uint32_t k=(uint32_t)f->in[0]<<24 | (uint32_t)f->in[1]<<16 |
                       (uint32_t)f->in[2]<<8 | f->in[3];
            if(!k || k>WB_SFTP_PACKET_MAX)return -1;
            f->need=4+(size_t)k;
        }
        if(f->need && f->got==f->need) {
            size_t k=0;
            if(wb_sftp_reply(&f->engine,f->in+4,f->need-4,f->out+4,
                             sizeof f->out-4,&k)!=0 || !k || k>sizeof f->out-4)return -1;
            f->out[0]=(uint8_t)(k>>24);f->out[1]=(uint8_t)(k>>16);
            f->out[2]=(uint8_t)(k>>8);f->out[3]=(uint8_t)k;
            f->got=f->need=f->sent=0;f->pending=k+4;
        }
    }
    return 1; /* yield to Vita foreground, power/veto and other SSH events */
#endif
}
