#ifndef WB_PANEL_CACHE_H
#define WB_PANEL_CACHE_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
/* Each GXM scanout buffer has its own cache. Only public local chrome is
 * retained; body content comes from the per-session mirror, never this cache.
 * Oversized labels disable caching rather than rendering a truncated value. */
typedef struct {uint64_t revision;bool valid,online;char pin[96],event[96];} wb_panel_cache;
static inline bool wb_panel_needs_raster(wb_panel_cache *c,uint64_t rev,bool online,
                                         const char *pin,const char *event){
    if(!pin)pin="";
    if(!event)event="";
    if(strlen(pin)>=sizeof c->pin || strlen(event)>=sizeof c->event){c->valid=false;return true;}
    if(c->valid && c->revision==rev && c->online==online &&
       !strcmp(c->pin,pin) && !strcmp(c->event,event))return false;
    c->revision=rev;c->online=online;c->valid=true;
    memcpy(c->pin,pin,strlen(pin)+1);memcpy(c->event,event,strlen(event)+1);
    return true;
}
#endif
