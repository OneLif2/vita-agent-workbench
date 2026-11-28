#ifndef WB_TTY_FILE_H
#define WB_TTY_FILE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "wb_sha256.h"

enum { WB_TTY_CHUNK=2048, WB_TTY_BATCH_FRAMES=8, WB_TTY_BATCH_BYTES=WB_TTY_CHUNK*WB_TTY_BATCH_FRAMES,
       WB_TTY_LINE=WB_TTY_CHUNK*2+32, WB_TTY_REPLY=WB_TTY_LINE+128 };
typedef struct {
    void *handle;
    /* Bounded heap allocation for put-batch only. offset remains the written
     * (not yet durable) watermark; buffered bytes MUST NOT appear in ACK/UI. */
    uint8_t *batch;
    size_t buffered;
    uint64_t size,offset;
    bool put;
    size_t n;
    wb_sha256 sha;
    char expected[65],line[WB_TTY_LINE],reply[WB_TTY_REPLY];
    uint8_t raw[WB_TTY_CHUNK];
} wb_tty_file;
/* Opaque, per-transfer storage. finish ALWAYS releases, commit only after verification. */
const char *wb_tty_vopen(bool put,const char *path,uint64_t expected,void **opaque,uint64_t *size);
const char *wb_tty_vopen_stream(const char *absolute,void **opaque);
const char *wb_tty_vmkdir(const char *absolute);
const char *wb_tty_vprobe(const char *absolute,const char **kind);
/* Non-stream, bounded interactive namespace operations. */
bool wb_tty_tree_command(const char *line,bool pty,char *reply,size_t cap);
const char *wb_tty_vwrite(void *opaque,const uint8_t *p,size_t n);
const char *wb_tty_vread(void *opaque,uint8_t *p,size_t cap,size_t *n);
const char *wb_tty_vfinish(void *opaque,bool commit,const char *shahex);
bool wb_tty_recognizes(const char *line);
const char *wb_tty_begin(wb_tty_file *f,const char *line);
/* 1 continue (reply may be empty while collecting a batch), 0 done/cancel,
 * -1 error (close channel after flushing receipt). */
int wb_tty_frame(wb_tty_file *f,bool *private_reply);
void wb_tty_abort(wb_tty_file *f);
#endif
