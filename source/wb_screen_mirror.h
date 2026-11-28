#ifndef WB_SCREEN_MIRROR_H
#define WB_SCREEN_MIRROR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* One bounded view of the admitted shell channel's committed terminal bytes.
 * Main-loop APIs only. Nothing here sees authentication, plaintext passwords,
 * SFTP packets, SSH requests or Windows desktop/window data. */
enum {WB_MIRROR_COLS=80, WB_MIRROR_ROWS=24, WB_MIRROR_MAX_COLS=512,
      WB_MIRROR_MAX_ROWS=128, WB_MIRROR_HEART=127, WB_MIRROR_HISTORY_ROWS=128};
void wb_mirror_begin(void);
void wb_mirror_reset(void);
void wb_mirror_geometry(unsigned columns,unsigned rows);
void wb_mirror_write(const uint8_t *bytes,size_t count);
bool wb_mirror_active(void);
const char *wb_mirror_row(unsigned row);
unsigned wb_mirror_cursor_row(void);
unsigned wb_mirror_cursor_col(void);
unsigned wb_mirror_cols(void);
unsigned wb_mirror_rows(void);
/* Local display only; never edit the negotiated PTY geometry or its input.
 * Positive scroll goes older; positive pan goes right. View rows are indexed
 * from the local screen top, independent of the live grid's first row. */
bool wb_mirror_scroll(int older_lines,unsigned visible_rows);
bool wb_mirror_pan(int right_cols,unsigned visible_cols);
unsigned wb_mirror_left(unsigned visible_cols);
void wb_mirror_follow(void);
bool wb_mirror_browsing(void);
unsigned wb_mirror_scroll_offset(unsigned visible_rows);
const char *wb_mirror_view_row(unsigned screen_row,unsigned visible_rows);
const uint8_t *wb_mirror_view_fg(unsigned screen_row,unsigned visible_rows);
uint64_t wb_mirror_revision(void);
#endif
