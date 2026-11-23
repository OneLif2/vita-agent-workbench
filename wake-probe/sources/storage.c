/* Versioned private savedata only; no Workbench key/approval data. */
#include "life.h"
#include "probe_io.h"
#include <psp2/apputil.h>
int lc_init(void){SceAppUtilInitParam p={0};SceAppUtilBootParam b={0};return sceAppUtilInit(&p,&b);}
int lc_load_arm(lc_arm*a){return wp_read_exact("savedata0:/wake-probe-arm.bin",a,sizeof *a);}
int lc_save_arm(const lc_arm*a){return wp_private_put("wake-probe-arm.bin",a,sizeof *a);}
int lc_load_trace(lc_trace*t){return wp_read_exact("savedata0:/wake-probe-ticks.bin",t,sizeof *t);}
int lc_save_trace(const lc_trace*t){return wp_private_put("wake-probe-ticks.bin",t,sizeof *t);}
