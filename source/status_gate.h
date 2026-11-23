#ifndef STATUS_GATE_H
#define STATUS_GATE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
/* Transport owns the authentication verification, session identity and
 * channel handles. Gate receives only trusted, monotonic app time. */
typedef struct {
    uint64_t deadline;
    uint64_t last_tick;
    unsigned status_count;
    bool authenticated;
    bool running;
} StatusGate;
static inline bool gate_authorize(StatusGate *g, uint64_t tick) {
    if(!g->running || tick<g->last_tick || tick>=g->deadline) {
        g->running=false;
        g->authenticated=false;
        return false;
    }
    g->last_tick=tick;
    return g->authenticated;
}
static inline unsigned gate_status(StatusGate *g,uint64_t tick,
                                  const char *name,size_t len) {
    if(!gate_authorize(g,tick) || !name || len!=6 ||
       memcmp(name,"status",6)!=0 || g->status_count>=2)return 0;
    return ++g->status_count;
}
#endif
