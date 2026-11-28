#ifndef VITA_STATUS_DISPLAY_H
#define VITA_STATUS_DISPLAY_H
#include <stdbool.h>
#include "wb_xfer_ui.h"
int display_init(void);
/* Only for an open listener. host_pin is the public host key fingerprint. */
int display_terminal(const char *host_pin, const char *event, bool agent_online);
int display_terminal_transfer(const char *host_pin,const char *event,bool agent_online,
                              const wb_xfer_ui *progress,uint64_t now_ms);
int display_frame_prompt(const char *,const char *,int,const char *);
int display_frame(const char *,const char *,int);
void display_plain_error(const char *);
void display_close(void);
/* Writes the last queued frame as a 24-bit BMP. Returns 1 on success. */
int display_capture(const char *path);
#endif
