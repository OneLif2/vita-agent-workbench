#include "terminal_status.h"
#include "active_terminal.h"
#include "status_gate.h"
#include <assert.h>
int main(void) {
    const char *run="1234567890ABCDEF";
    TerminalStatus t={0};
    StatusGate g={.running=true,.deadline=100};
    assert(!gate_status(&g,1,"status",6));
    g.authenticated=true;
    assert(!gate_status(&g,2,"prepare-install",15));
    assert(!gate_status(&g,3,"transfer-fixture",16));
    assert(!gate_status(&g,4,"status ",7));
    assert(!gate_status(&g,5,"status\n",7));
    assert(gate_status(&g,6,"status",6)==1);
    assert(terminal_status_format(&t,run,1,42));
    assert(strcmp(t.wire,"run=1234567890ABCDEF seq=1 app_uptime_ms=42\n")==0);
    assert(strcmp(t.screen,"STATUS 1: UPTIME MS 42")==0);
    assert(gate_status(&g,7,"status",6)==2);
    assert(terminal_status_format(&t,run,2,UINT64_MAX));
    assert(strcmp(t.wire,"run=1234567890ABCDEF seq=2 app_uptime_ms=18446744073709551615\n")==0);
    assert(strcmp(t.screen,"STATUS 2: UPTIME MS 18446744073709551615")==0);
    assert(strlen(t.screen)<50 && t.wire_len==strlen(t.wire));
    /* Real native frame uses x=36 with a 6*scale character advance. */
    assert(36+strlen(t.screen)*18<935);
    assert(terminal_right_x(sizeof TERMINAL_LABEL-1)>700);
    assert(terminal_right_x(sizeof TERMINAL_EXIT-1)+12*(sizeof TERMINAL_EXIT-1)==TERMINAL_RIGHT);
    assert(TERMINAL_RIGHT<935 && 72+7*TERMINAL_SMALL<TERMINAL_LINE1_Y);
    assert(TERMINAL_LINE1_Y+21<TERMINAL_LINE2_Y && TERMINAL_LINE2_Y+21<505);
    assert(36+64*12<960);
    assert(!gate_status(&g,8,"status",6));
    assert(!gate_authorize(&g,100));
    assert(!terminal_status_format(&t,"1234567890ABCDEf",1,1));
    assert(!terminal_status_format(&t,run,0,1));
    assert(!terminal_status_format(&t,run,3,1));
}
