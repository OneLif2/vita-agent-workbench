#ifndef WB_SHELL_CHANNEL_H
#define WB_SHELL_CHANNEL_H
#include "wb_shell.h"
#include <stdint.h>
#ifdef WB_TTY_FILE
#include "wb_tty_file.h"
#endif

typedef struct wb_shell_channel {
    wb_shell_engine shell;
    char line[WB_SH_LINE], pending[24576];
#ifdef WB_TTY_FILE
    uint8_t incoming[WB_TTY_LINE+2];
    wb_tty_file *file;
    bool private_pending, file_fault;
#else
    uint8_t incoming[256];
#endif
    size_t used, sent, queued, ri, rn;
#ifdef WB_SCREEN_MIRROR
    unsigned cols,rows;
    bool mirror_started; /* only after output committed on this admitted channel */
#endif
    uint64_t game_owner;
    unsigned escape;
    bool echo, ignore_lf, bad_line, closing, overflow;
} wb_shell_channel;

/* Nonblocking callbacks: read 0=would block,-2=EOF; write 0=would block. */
int wb_sh_start(wb_shell_channel *sh,bool tty);
int wb_sh_flush(wb_shell_channel *sh,void *io,int (*wr)(void*,const uint8_t*,size_t));
void wb_sh_set_geometry(wb_shell_channel *sh,int cols,int rows);
#ifdef WB_TTY_FILE
void wb_sh_abort_file(wb_shell_channel *sh);
#endif
int wb_sh_pump(wb_shell_channel *sh,void *io,
               int (*read_some)(void *,uint8_t *,size_t),
               int (*write_some)(void *,const uint8_t *,size_t),
               const wb_shell_ops *ops,unsigned *command_count);
#endif
