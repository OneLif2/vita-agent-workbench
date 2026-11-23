#ifndef WB_GAME_H
#define WB_GAME_H
#include <stddef.h>
#define WB_GAME_SCRIPT_SHA "ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d"
#define WB_GAME_RUNTIME "MicroPython 1.25.0 / wb-fixed-game"
typedef int (*wb_game_readline_fn)(void *ctx,char *line,size_t cap);
typedef int (*wb_game_write_fn)(void *ctx,const char *text,size_t bytes);
typedef int (*wb_game_delay_fn)(void *ctx,unsigned ms);
/* One VM, one separate worker with >=256 KiB stack. No script/path argument.
 * read: bytes excluding newline or <0 cancel. write/delay: 0 success, else cancel.
 * delay(0) must be a nonblocking cancellation poll. No callbacks may call into VM.
 * 0 complete, -2 detached/cancelled, -1 Python exception, -3 busy, -4 no memory/args. */
int wb_game_run(void *ctx,wb_game_readline_fn read,wb_game_write_fn write,wb_game_delay_fn delay);
#endif
