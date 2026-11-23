#ifndef WB_GAME_VITA_H
#define WB_GAME_VITA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
const char *wb_gv_start(const char *cwd, bool tty, const char *cmd, const uint8_t *tail, size_t n, int skip_lf, uint64_t *owner);
int wb_gv_tick(uint64_t owner,void *io,int (*rd)(void*,uint8_t*,size_t),int (*wr)(void*,const uint8_t*,size_t));
void wb_gv_stop(uint64_t owner);
#endif
