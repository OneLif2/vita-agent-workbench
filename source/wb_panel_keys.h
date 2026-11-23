#ifndef WB_PANEL_KEYS_H
#define WB_PANEL_KEYS_H
#include <stdint.h>
#include <stdbool.h>
#include <psp2/ctrl.h>
#include "wb_screen_mirror.h"
#include "wb_panel_geometry.h"
/* Single-key gestures, at most one per service tick. No sleeps/SSH I/O.
 * Fresh neutral sample required on entry, after conflicting chords or clock reversal. */
typedef struct {unsigned held;uint64_t since,last;bool neutral,repeating;} wb_panel_keys;
static inline unsigned wb_panel_action(wb_panel_keys *k,unsigned buttons,uint64_t now) {
    if(!buttons){*k=(wb_panel_keys){.neutral=true};return 0;}
    if(buttons!=SCE_CTRL_UP && buttons!=SCE_CTRL_DOWN && buttons!=SCE_CTRL_LEFT &&
       buttons!=SCE_CTRL_RIGHT && buttons!=SCE_CTRL_SQUARE){*k=(wb_panel_keys){0};return 0;}
    if(!k->neutral)return 0;
    if(!k->held){k->held=buttons;k->since=k->last=now;return buttons;}
    if(k->held!=buttons || now<k->last){*k=(wb_panel_keys){0};return 0;}
    if(buttons==SCE_CTRL_SQUARE || now-k->since<350 || now-k->last<100)return 0;
    k->last=now;k->repeating=true;return buttons;
}
static inline void wb_panel_apply(unsigned button,bool repeat) {
    const int lines=repeat?3:1;
    switch(button){
    case SCE_CTRL_UP: (void)wb_mirror_scroll(lines,WB_PANEL_ROWS);break;
    case SCE_CTRL_DOWN: (void)wb_mirror_scroll(-lines,WB_PANEL_ROWS);break;
    case SCE_CTRL_LEFT: (void)wb_mirror_pan(-8,WB_PANEL_COLS);break;
    case SCE_CTRL_RIGHT: (void)wb_mirror_pan(8,WB_PANEL_COLS);break;
    case SCE_CTRL_SQUARE: wb_mirror_follow();break;
    }
}
#endif
