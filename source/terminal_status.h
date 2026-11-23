#ifndef VITA_TERMINAL_STATUS_H
#define VITA_TERMINAL_STATUS_H
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char wire[112];
    char screen[64];
    unsigned wire_len;
} TerminalStatus;

static inline bool terminal_status_format(TerminalStatus *value, const char *run,
                                          unsigned seq, uint64_t ms) {
    if (!run || strlen(run) != 16 || strspn(run,"0123456789ABCDEF") != 16 ||
        seq < 1 || seq > 2) return false;
    const int n=snprintf(value->wire,sizeof value->wire,
        "run=%s seq=%u app_uptime_ms=%" PRIu64 "\n",run,seq,ms);
    const int r=snprintf(value->screen,sizeof value->screen,
        "STATUS %u: UPTIME MS %" PRIu64,seq,ms);
    if(n<=0||(size_t)n>=sizeof value->wire||r<=0||(size_t)r>=sizeof value->screen)
        return false;
    value->wire_len=(unsigned)n;
    return true;
}
#endif
