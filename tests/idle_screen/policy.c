#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "wb_idle_screen.h"

static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)

static int step_commit(wb_idle_screen *s,uint64_t now,bool activity,bool enabled) {
    int action=wb_idle_screen_step(s,now,activity,enabled);
    wb_idle_screen_result(s,now,action,0);
    return action;
}

int main(void) {
    wb_idle_screen s = {0};
    CHECK(step_commit(&s, 0, false, true) == WB_IDLE_NONE);
    CHECK(s.initialized && !s.off && s.last_activity_ms == 0);
    CHECK(step_commit(&s, 899999, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 900000, false, true) == WB_IDLE_OFF);
    CHECK(s.off);
    CHECK(step_commit(&s, 900001, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 2700000, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 2700001, true, true) == WB_IDLE_ON);
    CHECK(!s.off && s.last_activity_ms == 2700001);
    CHECK(step_commit(&s, 3600000, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 3600001, false, true) == WB_IDLE_OFF);

    s = (wb_idle_screen){0};
    CHECK(step_commit(&s, 100, false, true) == WB_IDLE_NONE);
    /* Local activity wins even exactly on the old deadline. */
    CHECK(step_commit(&s, 900100, true, true) == WB_IDLE_NONE);
    CHECK(!s.off && s.last_activity_ms == 900100);
    CHECK(step_commit(&s, 1800099, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 1800100, false, true) == WB_IDLE_OFF);

    s = (wb_idle_screen){0};
    CHECK(step_commit(&s, 1000, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 899999, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 10, false, true) == WB_IDLE_NONE);
    CHECK(!s.off && s.last_activity_ms == 10);
    CHECK(step_commit(&s, 900009, false, true) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 900010, false, true) == WB_IDLE_OFF);

    s = (wb_idle_screen){0};
    CHECK(step_commit(&s, 0, false, false) == WB_IDLE_NONE);
    CHECK(step_commit(&s, 1800000, false, false) == WB_IDLE_NONE);
    CHECK(!s.off);
    s = (wb_idle_screen){.initialized=true};
    CHECK(wb_idle_screen_step(&s, 900000, false, true) == WB_IDLE_OFF);
    CHECK(!s.off); /* Intent alone is not native-call success. */
    wb_idle_screen_result(&s, 900000, WB_IDLE_OFF, -1);
    CHECK(!s.off && s.retry_after_ms == 910000);
    CHECK(wb_idle_screen_step(&s, 909999, false, true) == WB_IDLE_NONE);
    CHECK(wb_idle_screen_step(&s, 910000, false, true) == WB_IDLE_OFF);
    wb_idle_screen_result(&s, 910000, WB_IDLE_OFF, 0);
    CHECK(s.off && !s.retry_after_ms);
    CHECK(wb_idle_screen_step(&s, 910001, true, true) == WB_IDLE_ON);
    wb_idle_screen_result(&s, 910001, WB_IDLE_ON, -1);
    CHECK(s.off && s.retry_after_ms == 920001);
    CHECK(wb_idle_screen_step(&s, 920000, false, true) == WB_IDLE_NONE);
    CHECK(wb_idle_screen_step(&s, 920001, false, true) == WB_IDLE_ON);
    wb_idle_screen_result(&s, 920001, WB_IDLE_ON, 0);
    CHECK(!s.off);
    wb_idle_screen_result(&s, UINT64_MAX-1, WB_IDLE_OFF, -1);
    CHECK(s.retry_after_ms == UINT64_MAX);
    CHECK(wb_idle_screen_step(NULL, 0, false, true) == WB_IDLE_NONE);
    wb_idle_screen_result(NULL, 0, WB_IDLE_OFF, 0);
    puts("PASS idle policy: 15-minute boundary, one-shot off, local wake/reset, reversal and disabled mode");
    printf("policy assertions=%u; pure host code, no Vita\n", checks);
    return 0;
}
