#ifndef VITA_LAUNCH_HANDOFF_H
#define VITA_LAUNCH_HANDOFF_H
#include <stdbool.h>
#include <stdint.h>

typedef enum { LH_PRE_GUARD_STOP, LH_POST_GUARD_STOP, LH_CALLED } LaunchPhase;
typedef struct { LaunchPhase phase; int32_t rc; } LaunchHandoff;
typedef struct {
    bool (*guard_before)(void);
    void (*stop_listener)(void);
    bool (*guard_after)(void);
    void (*precall_note)(void);
    int32_t (*call_fixed_appmgr)(void);
} LaunchOps;

/* Testable production sequencing. No fallback when AppMgr refuses. */
static inline LaunchHandoff launch_handoff(const LaunchOps *ops) {
    if(!ops->guard_before())return (LaunchHandoff){LH_PRE_GUARD_STOP,0};
    ops->stop_listener();
    if(!ops->guard_after())return (LaunchHandoff){LH_POST_GUARD_STOP,0};
    ops->precall_note();
    /* Recheck after synchronous diagnostics; do not log between this and AppMgr. */
    if(!ops->guard_after())return (LaunchHandoff){LH_POST_GUARD_STOP,0};
    return (LaunchHandoff){LH_CALLED,ops->call_fixed_appmgr()};
}

typedef enum { LH_ACK, LH_NOEXEC, LH_OTHER } LaunchResult;
static inline LaunchResult launch_reply(int32_t rc,uint32_t noexec) {
    return rc==0?LH_ACK:(uint32_t)rc==noexec?LH_NOEXEC:LH_OTHER;
}
#endif
