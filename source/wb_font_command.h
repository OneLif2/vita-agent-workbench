#ifndef WB_FONT_COMMAND_H
#define WB_FONT_COMMAND_H
/* Small preferences, not authority: no supplied path and no OS font loader.
 * Two 16-byte records preserve the last valid preference across torn writes. */
#include <stdint.h>
#include <string.h>
#include "wb_panel_geometry.h"
#include "wb_cmd.h"
#include "wb_out.h"
#include "wb_jetbrains_license.h"

enum {WB_FONT_REC=16};
typedef struct {uint32_t generation;unsigned slot;} wb_font_state;
typedef struct {
    bool (*read)(unsigned slot,uint8_t dst[WB_FONT_REC]);
    bool (*write)(unsigned slot,const uint8_t src[WB_FONT_REC]);
} wb_font_storage;
static uint32_t wb_fget32(const uint8_t *s){
    return (uint32_t)s[0]|((uint32_t)s[1]<<8)|((uint32_t)s[2]<<16)|((uint32_t)s[3]<<24);
}
static void wb_fput32(uint8_t *p,uint32_t v){
    for(unsigned k=0;k<4;k++)p[k]=(uint8_t)(v>>(8*k));
}
/* Accidental-corruption checksum only, not cryptographic authentication. */
static uint32_t wb_fsum(const uint8_t *p){
    uint32_t x=2166136261u;
    for(unsigned i=0;i<12;i++)x=(x^p[i])*16777619u;
    return x;
}
static void wb_fencode(uint8_t p[WB_FONT_REC],uint32_t gen,wb_type_style s){
    memcpy(p,"WBF1",4);wb_fput32(p+4,gen);
    p[8]=(uint8_t)s.family;p[9]=(uint8_t)s.scale;p[10]=(uint8_t)s.gap_x;p[11]=(uint8_t)s.gap_y;
    wb_fput32(p+12,wb_fsum(p));
}
static void wb_font_boot(wb_font_state *st,const wb_font_storage *fs){
    wb_type_style best=WB_TYPE_DEFAULT;
    *st=(wb_font_state){0,0};
    for(unsigned slot=0;slot<2;slot++){
        uint8_t p[WB_FONT_REC];
        if(!fs->read(slot,p)||memcmp(p,"WBF1",4)||wb_fget32(p+12)!=wb_fsum(p))continue;
        uint32_t gen=wb_fget32(p+4);
        wb_type_style v={.family=p[8],.scale=p[9],.gap_x=p[10],.gap_y=p[11]};
        if(gen>st->generation&&wb_type_valid(v)){st->generation=gen;st->slot=slot;best=v;}
    }
    (void)wb_type_set(best);
}
static int wb_fnumber(const char *v,unsigned *n){
    if(!v[0] || (v[0]=='0' && v[1]))return 0;
    unsigned t=0;
    for(unsigned i=0;v[i];i++){
        if(i>=2||v[i]<'0'||v[i]>'9')return 0;
        t=10u*t+(unsigned)(v[i]-'0');
    }
    *n=t;return 1;
}
static bool wb_fsame(wb_type_style a,wb_type_style b){
    return a.family==b.family&&a.scale==b.scale&&a.gap_x==b.gap_x&&a.gap_y==b.gap_y;
}
static int wb_font_result(wb_out *out,int *status,const char *msg){
    *status=1;return wb_out_puts(out,msg);
}
static int wb_font_command(const wb_cmd *cmd,wb_out *out,int *status,wb_font_state *st,const wb_font_storage *fs){
    wb_type_style old=wb_type_get(),next=old;
    *status=0;
    if(cmd->argc==1 && !strcmp(cmd->argv[0],"license"))
        return wb_out_puts(out,wb_jb_license);
    if(cmd->argc==1 && !strcmp(cmd->argv[0],"reset"))next=WB_TYPE_DEFAULT;
    else if(cmd->argc==5 && !strcmp(cmd->argv[0],"set")){
        const char *family=cmd->argv[1];
        if(!strcmp(family,"classic"))next.family=WB_TYPE_CLASSIC;
        else if(!strcmp(family,"jetbrains"))next.family=WB_TYPE_JETBRAINS;
        else return wb_font_result(out,status,"ERR font-family: classic or jetbrains\n");
        if(!wb_fnumber(cmd->argv[2],&next.scale)||!wb_fnumber(cmd->argv[3],&next.gap_x)||
           !wb_fnumber(cmd->argv[4],&next.gap_y)||!wb_type_valid(next))
            return wb_font_result(out,status,"ERR font-value: scale=1..3 gap_x=0..4 gap_y=2..10\n");
    }else if(cmd->argc!=0)return wb_font_result(out,status,"ERR font-syntax; see help font\n");
    if(!wb_fsame(next,old)){
        uint8_t rec[WB_FONT_REC],check[WB_FONT_REC];unsigned slot=st->generation?1u-st->slot:0;
        if(st->generation==UINT32_MAX)return wb_font_result(out,status,"ERR font-store full; current display unchanged\n");
        wb_fencode(rec,st->generation+1,next);
        if(!fs->write(slot,rec)||!fs->read(slot,check)||memcmp(rec,check,sizeof rec))
            return wb_font_result(out,status,"ERR font-store unverified; current display unchanged\n");
        if(!wb_type_set(next))return wb_font_result(out,status,"ERR font-renderer rejected preference\n");
        ++st->generation;st->slot=slot;
    }
    return wb_out_printf(out,"font family=%s scale=%u gap_x=%u gap_y=%u cols=%u rows=%u\n",
        next.family==WB_TYPE_JETBRAINS?"jetbrains":"classic",next.scale,next.gap_x,next.gap_y,
        wb_type_cols(next),wb_type_rows(next));
}
#endif
