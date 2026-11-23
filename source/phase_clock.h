#ifndef INA_PHASE_CLOCK
#define INA_PHASE_CLOCK
#include <stdint.h>
typedef struct {const char *name;uint64_t started,finished;int rc;} PhaseClock;
static inline uint64_t phase_elapsed(PhaseClock p,uint64_t now){
    const uint64_t end=p.finished?p.finished:now;
    return end>=p.started?end-p.started:UINT64_MAX;
}
#endif
