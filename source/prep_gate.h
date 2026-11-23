#ifndef INA_PREP_GATE_H
#define INA_PREP_GATE_H
#include <stdint.h>
#include <stdbool.h>
enum {VITA_PREP_MS=300000};
typedef enum { PREP_WAIT=0,PREP_ENABLE,PREP_EXIT,PREP_EXPIRED,PREP_FOCUS_LOST,PREP_INPUT_ERROR,PREP_RENDER_ERROR,PREP_CLOCK_ERROR } PrepResult;
typedef struct {uint64_t start,last;bool armed;} PrepGate;
static inline uint64_t prep_seconds_left(const PrepGate *p,uint64_t t){
    return t>=p->start&&t-p->start<VITA_PREP_MS? (VITA_PREP_MS-(t-p->start)+999u)/1000u:0;
}
static inline PrepResult prep_tick(PrepGate *p,uint64_t t,bool focused,bool pad_ok,bool rendered,
    unsigned mask,unsigned cross,unsigned start){
    if(t<p->start||t<p->last)return PREP_CLOCK_ERROR;
    p->last=t;
    if(t-p->start>=VITA_PREP_MS)return PREP_EXPIRED;
    if(!focused)return PREP_FOCUS_LOST;
    if(!pad_ok)return PREP_INPUT_ERROR;
    if(!rendered)return PREP_RENDER_ERROR;
    mask &= cross|start;
    if(!mask){p->armed=true;return PREP_WAIT;}
    if(!p->armed)return PREP_WAIT;
    p->armed=false;
    return mask==cross?PREP_ENABLE:mask==start?PREP_EXIT:PREP_WAIT;
}
#endif
