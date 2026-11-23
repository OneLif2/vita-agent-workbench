#ifndef WB_SFTP_FRAME_H
#define WB_SFTP_FRAME_H
#include "wb_sftp_ro.h"
/* One ordered request/reply at a time. SSH may split either at any byte;
 * pipelined requests stay in the ordinary SSH flow-control window. */
typedef struct wb_sftp_frame {
    wb_sftp_ro engine;
    uint8_t in[4+WB_SFTP_PACKET_MAX], out[4+WB_SFTP_REPLY_MAX];
    size_t got, need, sent, pending;
} wb_sftp_frame;
typedef int (*wb_sf_read)(void *,uint8_t *,size_t);
typedef int (*wb_sf_write)(void *,const uint8_t *,size_t);
/* callbacks: >0 progress, 0 would block, -1 error, -2 EOF (read only).
 * pump: 1 keep channel, 0 clean EOF at a packet boundary, -1 close on error. */
int wb_sf_pump(wb_sftp_frame *f,void *ctx,wb_sf_read rd,wb_sf_write wr);
#endif
