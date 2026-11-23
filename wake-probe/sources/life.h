#ifndef LIFE_H
#define LIFE_H
#include <stdint.h>
#include <stddef.h>
#define LC_MAGIC UINT32_C(0x57424331)
#define LC_TRACE UINT32_C(0x57425431)
#define LC_SPAN UINT64_C(120000000)
#define LC_STEP UINT64_C(5000000)
#define LC_CAP 24u
typedef struct {uint32_t magic,enabled;uint64_t start;} lc_arm;
typedef struct {uint32_t magic,count;uint64_t start,us[LC_CAP];} lc_trace;
static inline int lc_live(const lc_arm *a,uint64_t now) {
    return a&&a->magic==LC_MAGIC&&a->enabled==1&&a->start>0&&now>=a->start&&now-a->start<LC_SPAN;
}
static inline int lc_valid(const lc_trace *t) {
    if(!t||t->magic!=LC_TRACE||!t->start||t->count>LC_CAP)return 0;
    for(unsigned i=0;i<t->count;i++) if(t->us[i]<t->start||t->us[i]-t->start>=LC_SPAN||
       (i&&(t->us[i]<t->us[i-1]||t->us[i]-t->us[i-1]<LC_STEP))) return 0;
    return 1;
}
static inline int lc_tick(const lc_arm *a,lc_trace *t,uint64_t now) {
    if(!lc_valid(t)||!lc_live(a,now)||a->start!=t->start||t->count>=LC_CAP)return 0;
    if(t->count && (now<t->us[t->count-1]||now-t->us[t->count-1]<LC_STEP))return 0;
    t->us[t->count++]=now;return 1;
}
/* Accept only neutral -> one exact button -> neutral, never a held/combined button. */
static inline int lc_gesture(int *stage,uint32_t keys,uint32_t wanted) {
    if(!keys){int was=*stage;*stage=1;return was==2;}
    if(keys==wanted&&*stage){*stage=2;return 0;}
    *stage=0;return 0;
}
int lc_load_arm(lc_arm *a);
int lc_save_arm(const lc_arm *a);
int lc_load_trace(lc_trace *t);
int lc_save_trace(const lc_trace *t);
int lc_init(void);
#endif
