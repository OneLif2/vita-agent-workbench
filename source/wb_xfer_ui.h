#ifndef WB_XFER_UI_H
#define WB_XFER_UI_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* Presentation only. This progress counts TTY data bytes, NOT a verified
 * publication. Commit/readback/SHA and the wire receipt are independent. */
typedef struct {unsigned pct;char text[80];} wb_xfer_ui;
static inline void wb_xfer_format(wb_xfer_ui *m,bool put,uint32_t done,uint32_t total,uint64_t bps){
    if(done>total)done=total;
    m->pct=total?(unsigned)((uint64_t)done*100/total):0;
    char rate[24],eta[24];
    if(bps>=1000000)snprintf(rate,sizeof rate,"%llu.%02u MB/s",
        (unsigned long long)(bps/1000000),(unsigned)(bps%1000000)/10000);
    else snprintf(rate,sizeof rate,"%u.%u KB/s",(unsigned)(bps/1000),(unsigned)(bps%1000)/100);
    if(done==total)snprintf(eta,sizeof eta,"WAIT RECEIPT");
    else if(!bps)snprintf(eta,sizeof eta,"--");
    else snprintf(eta,sizeof eta,"%llus",(unsigned long long)(1+(total-done-1)/bps));
    snprintf(m->text,sizeof m->text,"%s %u%%  %u/%u B  %s  ETA %s",put?"PUT":"GET",
             m->pct,(unsigned)done,(unsigned)total,rate,eta);
}
static inline void wb_xfer_qty(uint64_t bytes,char out[32]){
    if(bytes>=1048576u)snprintf(out,32,"%llu.%02u MB",
        (unsigned long long)(bytes/1048576u),(unsigned)((bytes%1048576u)*100u/1048576u));
    else if(bytes>=1024u)snprintf(out,32,"%llu.%u KB",
        (unsigned long long)(bytes/1024u),(unsigned)((bytes%1024u)*10u/1024u));
    else snprintf(out,32,"%llu B",(unsigned long long)bytes);
}
static inline void wb_xfer_rate(uint64_t bps,char out[32]){
    if(bps>=1000000)snprintf(out,32,"%llu.%02u MB/s",
        (unsigned long long)(bps/1000000),(unsigned)(bps%1000000)/10000);
    else snprintf(out,32,"%u.%u KB/s",(unsigned)(bps/1000),(unsigned)(bps%1000)/100);
}
static inline void wb_xfer_format_pct(wb_xfer_ui *m,const char *tag,uint64_t done,uint64_t total,uint64_t bps){
    if(total && done>total)done=total;
    m->pct=total?(done>=total?100u:(unsigned)((done*100u)/total)):0u;
    char dqty[32],tqty[32],rate[32],eta[32];
    wb_xfer_qty(done,dqty);
    wb_xfer_qty(total,tqty);
    wb_xfer_rate(bps,rate);
    if(total && done>=total)snprintf(eta,sizeof eta,"VERIFY");
    else if(!bps || !total)snprintf(eta,sizeof eta,"--");
    else snprintf(eta,sizeof eta,"%llus",(unsigned long long)(1u+(total-done-1u)/bps));
    snprintf(m->text,sizeof m->text,"%.10s %3u%%  %.14s/%.14s  %.14s  ETA %.10s",tag,m->pct,dqty,tqty,rate,eta);
}
static inline void wb_xfer_format_stream(wb_xfer_ui *m,const char *tag,uint64_t done,uint64_t bps){
    m->pct=(unsigned)(((done/65536u)%96u)+4u);
    char qty[32],rate[32];
    wb_xfer_qty(done,qty);
    wb_xfer_rate(bps,rate);
    snprintf(m->text,sizeof m->text,"%.10s --%%  %.14s  %.14s  ACTIVE",tag,qty,rate);
}
static inline bool wb_xfer_matches(const wb_xfer_ui *a,const wb_xfer_ui *b){
    if(!a||!b)return a==b;
    return a->pct==b->pct&&!strcmp(a->text,b->text);
}
#endif
