#ifndef WB_DF_HUMAN_H
#define WB_DF_HUMAN_H
/* Display only. Never feed rounded values back into staging/budget policy. */
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include "wb_out.h"
#include "wb_err.h"
enum { WB_DF_FIELD = 24 };
static inline void wb_df_units(char out[WB_DF_FIELD],uint64_t v){
    static const char *const units[]={"B","KiB","MiB","GiB","TiB","PiB","EiB"};
    uint64_t unit=1;unsigned i=0;
    while(i+1<sizeof units/sizeof units[0] && v/unit>=1024u){unit*=1024u;++i;}
    if(!i)(void)snprintf(out,WB_DF_FIELD,"%" PRIu64 " B",v);
    else (void)snprintf(out,WB_DF_FIELD,"%" PRIu64 ".%u %s",v/unit,
                        (unsigned)((v%unit)*10u/unit),units[i]);
}
static inline int wb_df_human(wb_out *out,int api,uint64_t total,uint64_t avail){
    if(api<0||!total||avail>total){
        (void)wb_out_printf(out,"ERR space-unavailable api=0x%08X\n",(unsigned)api);return WB_E_IO;
    }
    const uint64_t used=total-avail;
    char t[WB_DF_FIELD],u[WB_DF_FIELD],a[WB_DF_FIELD];
    wb_df_units(t,total);wb_df_units(u,used);wb_df_units(a,avail);
    /* Smallest percent whose exact fraction covers used (df rounds use% up).
     * Decompose total before multiplication to support UINT64_MAX capacities. */
    unsigned pct=0;
    while(pct<100 && (total/100u)*pct+((total%100u)*pct)/100u < used)++pct;
    return wb_out_printf(out,"Filesystem       Size        Used       Avail   Use%%  Mounted on\n"
                             "ux0:       %10s  %10s  %10s   %3u%%  ux0:/\n",t,u,a,pct);
}
#endif
