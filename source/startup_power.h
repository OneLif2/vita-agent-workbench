#ifndef INA_STARTUP_POWER
#define INA_STARTUP_POWER
#include <stdint.h>
#include <stdbool.h>

/* The pre-network power registration window ONLY. Do not use this filter
 * for callbacks after arming. Numeric values from VitaSDK psp2common/power.h. */
enum { POWER_FIRST_MS=200, POWER_QUIET_MS=120, POWER_WINDOW_MS=500, POWER_ACK_MS=30000,
       POWER_EMPTY_REGISTRATION_MS=20 };
enum { WB_AFTER_RESUME=0x80, WB_BATTERY_ONLINE=0x100, WB_AC_ONLINE=0x1000 };
typedef struct { uint32_t invocations,bits; int count; } PowerSeen;
typedef struct {
    uint64_t last;
    bool sampled, saw_callback, waiting_ack;
    int initial_ac;
    uint32_t bits;
} PowerStart;
typedef enum {
    PW_WAIT, PW_READY, PW_LOCAL_ACK,
    PW_CLOCK, PW_FOCUS, PW_CB, PW_SUPPLY, PW_SUSPEND, PW_LOW,
    PW_REPEAT, PW_LATE, PW_FLAGS, PW_AC_MISMATCH, PW_UI, PW_CANCEL
} PowerStep;

static inline PowerStep power_start_step(PowerStart *s, uint64_t elapsed, bool focused,
                                          int cb, PowerSeen v, int ac, int suspend, int low) {
    if (elapsed < s->last || elapsed > (s->waiting_ack ? POWER_ACK_MS : POWER_WINDOW_MS)) return PW_CLOCK;
    s->last = elapsed;
    if (cb < 0 || cb > 1) return PW_CB;
    if (!focused) return PW_FOCUS;
    if (suspend != 0) return PW_SUSPEND;
    if (low != 0) return PW_LOW;
    if ((ac != 0 && ac != 1) || (s->sampled && s->initial_ac != ac)) return PW_SUPPLY;
    const bool first_sample = !s->sampled;
    s->sampled = true;
    s->initial_ac = ac;
    if (!v.invocations) {
        if (s->saw_callback || v.count || v.bits || cb) return PW_CB;
        return elapsed >= POWER_FIRST_MS ? PW_READY : PW_WAIT;
    }
    /* Dispatch is tracked by our own callback; do not assume its first
     * observation must coincide with a return of 1 from CheckCallback. */
    if (v.invocations != 1 || v.count != 1) return PW_REPEAT;
    if (v.bits & ~(uint32_t)(WB_AC_ONLINE|WB_BATTERY_ONLINE|WB_AFTER_RESUME)) return PW_FLAGS;
    /* A real 01.11-HF1 registration on battery dispatched once at dt=0 with
     * no event bits. This is not "no callback", nor evidence that it is safe
     * to arm automatically. Admit only this first-sample shape to settling
     * and the fresh physical confirmation below. Later notifications fail. */
    if (!v.bits && !s->saw_callback &&
        (!first_sample || cb != 1 || ac != 0 || elapsed > POWER_EMPTY_REGISTRATION_MS)) return PW_FLAGS;
    if (((v.bits & WB_AC_ONLINE) != 0) != (ac == 1)) return PW_AC_MISMATCH;
    if (!s->saw_callback) {
        if (elapsed > POWER_FIRST_MS) return PW_LATE;
        s->saw_callback = true;
        s->bits = v.bits;
    } else if (v.bits != s->bits || cb != 0) return PW_REPEAT;
    if (elapsed < POWER_FIRST_MS + POWER_QUIET_MS) return PW_WAIT;
    /* AFTER_SYSTEM_RESUME is NOT a benign supply flag. A single such
     * registration notification must never automatically re-arm anything. */
    if (!v.bits || (v.bits & WB_AFTER_RESUME)) { s->waiting_ack = true; return PW_LOCAL_ACK; }
    return PW_READY;
}
#endif
