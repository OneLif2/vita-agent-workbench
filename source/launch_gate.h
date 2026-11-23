#ifndef VITA_LAUNCH_GATE_H
#define VITA_LAUNCH_GATE_H
#include "fresh_choice.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define LAUNCH_TITLE "INAP00015"
typedef enum {L_IDLE,L_WAIT,L_APPROVED,L_CANCELED} LaunchState;
typedef struct {LaunchState state;uint64_t since,deadline;bool neutral;} LaunchGate;
static inline bool launch_offer(LaunchGate *g,bool auth,const char *cmd,size_t len,uint64_t now) {
    if(!auth||g->state!=L_IDLE||!cmd||len!=11||memcmp(cmd,"launch-test",11)||now>UINT64_MAX-30000)
        return false;
    *g=(LaunchGate){.state=L_WAIT,.since=now,.deadline=now+30000};
    return true;
}
static inline LaunchState launch_poll(LaunchGate *g,bool healthy,uint64_t now,unsigned buttons,
                                     unsigned cross,unsigned circle) {
    if(g->state!=L_WAIT)return g->state;
    if(!healthy||(buttons&(cross|circle))!=buttons||now<g->since||now>=g->deadline)return g->state=L_CANCELED;
    const int action=fresh_choice(&g->neutral,buttons,cross,circle);
    if(action)return g->state=action>0?L_APPROVED:L_CANCELED;
    return g->state;
}
static inline bool launch_approved_now(const LaunchGate *g,bool guards,uint64_t now){
    return g->state==L_APPROVED&&guards&&now>=g->since&&now<g->deadline;
}
#endif
