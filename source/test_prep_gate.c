#include <assert.h>
#include "prep_gate.h"
#define T(t,m) prep_tick(&p,t,true,true,true,m,1,2)
int main(void){
    PrepGate p={.start=500,.last=500};
    assert(prep_seconds_left(&p,500)==300);
    assert(T(500,1)==PREP_WAIT);assert(T(501,0)==PREP_WAIT);
    assert(T(502,3)==PREP_WAIT);assert(T(503,1)==PREP_WAIT);
    assert(T(504,0)==PREP_WAIT);assert(T(300499,1)==PREP_ENABLE);
    p=(PrepGate){.start=500,.last=500};
    assert(T(500,0)==PREP_WAIT);assert(prep_seconds_left(&p,300499)==1);
    assert(T(300500,1)==PREP_EXPIRED);assert(prep_seconds_left(&p,300500)==0);
    p=(PrepGate){.start=500,.last=500};
    assert(T(500,0)==PREP_WAIT);assert(T(501,2)==PREP_EXIT);
    assert(prep_tick(&p,502,false,true,true,0,1,2)==PREP_FOCUS_LOST);
    assert(prep_tick(&p,503,true,false,true,0,1,2)==PREP_INPUT_ERROR);
    assert(prep_tick(&p,504,true,true,false,0,1,2)==PREP_RENDER_ERROR);
    assert(T(503,1)==PREP_CLOCK_ERROR);
}
