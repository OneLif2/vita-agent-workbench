#ifndef WB_GAME_IO_H
#define WB_GAME_IO_H
/* C11. One main-loop producer/consumer, one approved runner worker. No OS exec.
 * Main-loop operations must run on the SAME thread as Workbench SSH service.
 * Worker operations must run on ONE other thread only, never the SSH thread. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#define WBG_COMMAND "python3 tictactoe_ai.py"
#define WBG_SCRIPT_SHA "ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d"
enum { WBG_LINE=96, WBG_INPUT_LINES=8, WBG_TX=4096, WBG_WRITE_MAX=1024, WBG_ECHO=512 };
enum { WBG_IDLE, WBG_ACTIVE, WBG_DONE, WBG_CANCELLED };
enum { WBG_NORMAL, WBG_INTERRUPT, WBG_EOF, WBG_DISCONNECT, WBG_BAD_INPUT,
       WBG_INPUT_LIMIT, WBG_BAD_OUTPUT, WBG_RUNNER_FAILED, WBG_ACCESS_REVOKED };
/* All counts SPSC. No heap, sleep, interpreter, sockets, or key/trust policy here. */
typedef struct {
    uint64_t owner;
    atomic_uint state, cause, rx_w, rx_r, tx_w, tx_r, waiting, echo_owed;
    uint8_t tx[WBG_TX], echo[WBG_ECHO];
    char lines[WBG_INPUT_LINES][WBG_LINE+1], edit[WBG_LINE+1];
    unsigned len, echo_r, echo_w;
    int tty, skip_lf;
} wb_game_io;
typedef int (*wbg_read_fn)(void*,uint8_t*,size_t); /* 0 again, -2 EOF, other negative error */
typedef int (*wbg_write_fn)(void*,const uint8_t*,size_t); /* 0 again, negative error */
/* Main only. init once or after game channel has CLOSED and worker has JOINED.
 * Nonzero unique lifetime token; pass the approved immutable package script
 * SHA rehashed by caller, not claimed by command input. Never attach second
 * owner, never resume shell editor or reuse owner/token at end of game. */
void wbg_init(wb_game_io*);
int wbg_start(wb_game_io*,uint64_t owner,const char *exact_command,
              const char *verified_script_sha,int admitted,int tty);
/* Pass unread editor bytes after the launch command (including queued paste);
 * skip_start_lf=1 if editor consumed a CR launching the game. Pass to game
 * only; clear editor's queued indices; never pass them back to WB. */
int wbg_prefeed(wb_game_io*,uint64_t owner,const uint8_t*,size_t,int skip_start_lf);
/* 1 continue, 0 normal drained finish (close game-only channel), -1 ended,
 * -2 caller token incorrect (never cancels or accesses owner's stream).
 * Main calls even on a quiet connection. Recheck core admission every tick. */
int wbg_tick(wb_game_io*,uint64_t owner,int admitted,void *io,wbg_read_fn,wbg_write_fn);
void wbg_disconnect(wb_game_io*,uint64_t owner);
/* Worker only: 1 accepted/read, 0 would block, -1 stop/cancelled.
 * write is ALL-OR-NOTHING; on 0 retry same span from worker. Ready output
 * includes prompts without LF. Cooked text: printable ASCII, HT, LF, and
 * complete UTF-8 U+2665; do not split inside a code point. */
int wbg_write(wb_game_io*,const uint8_t*,size_t);
int wbg_flushed(wb_game_io*); /* 1 accepted by transport; not visibility proof */
int wbg_readline(wb_game_io*,char dst[WBG_LINE+1]); /* logical line, newline stripped */
void wbg_finish(wb_game_io*,int success);
#endif
