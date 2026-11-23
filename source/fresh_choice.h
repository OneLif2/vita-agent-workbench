#ifndef INA_FRESH_CHOICE_H
#define INA_FRESH_CHOICE_H
#include <stdbool.h>
static inline int fresh_choice(bool *neutral,unsigned keys,unsigned accept,unsigned cancel) {
    keys &= accept|cancel;
    if(!keys){*neutral=true;return 0;}
    if(!*neutral)return 0;
    *neutral=false;
    return keys==accept?1:keys==cancel?-1:0;
}
#endif
