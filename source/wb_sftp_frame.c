#include "wb_sftp_frame.h"
int wb_sf_pump(wb_sftp_frame *f,void *ctx,wb_sf_read rd,wb_sf_write wr) {
    for (unsigned step=0;step<12;step++) {
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
}
