#ifndef VITA_ACTIVE_TERMINAL_H
#define VITA_ACTIVE_TERMINAL_H
#include <stdbool.h>
#include <stddef.h>
typedef enum {ACTIVE_GO,ACTIVE_USER_EXIT,ACTIVE_INPUT_ERROR,ACTIVE_GUARD_LOST} ActiveState;
static inline ActiveState active_check(bool input,bool start,bool healthy,void (*stop)(void)) {
    ActiveState state=!input?ACTIVE_INPUT_ERROR:start?ACTIVE_USER_EXIT:
                      !healthy?ACTIVE_GUARD_LOST:ACTIVE_GO;
    if(state!=ACTIVE_GO)stop();
    return state;
}
typedef enum {PERMIT_READY,PERMIT_OWNER_ENDED,PERMIT_ATTEMPTS_SPENT} PermitState;
static inline PermitState permit_state(bool session,bool accepted,unsigned attempts,unsigned cap) {
    if(accepted)return session?PERMIT_READY:PERMIT_OWNER_ENDED;
    return attempts>=cap?PERMIT_ATTEMPTS_SPENT:PERMIT_READY;
}
enum {TERMINAL_RIGHT=914, TERMINAL_SMALL=2, TERMINAL_LINE1_Y=156, TERMINAL_LINE2_Y=203};
#define TERMINAL_LABEL "SSH STATUS"
#define TERMINAL_EXIT "START EXITS"
static inline int terminal_right_x(size_t count){return TERMINAL_RIGHT-6*TERMINAL_SMALL*(int)count;}
#endif
