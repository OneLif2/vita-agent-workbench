/* Opaque local strip at the live cursor row (never emitted to SSH). The meter
 * changes only these 30 visible scan lines; the other buffer may still need
 * an entire mirror redraw if its base content differs. */
enum { WB_XFER_STRIP_H=30 };
static void wb_xfer_draw(uint32_t *p,const wb_xfer_ui *m){
    const wb_type_style style=wb_type_get();
#ifdef WB_SHELL2
    unsigned y=356;
    const uint32_t card_bg=COLOR(22,27,34);
    const uint32_t bar_track=COLOR(33,38,45);
    const uint32_t bar_fill=COLOR(39,201,63);
    const uint32_t text_fg=COLOR(240,246,252);
#else
    unsigned y=225;
    const uint32_t card_bg=LIVE_TERMINAL_BG;
    const uint32_t bar_track=COLOR(61,70,73);
    const uint32_t bar_fill=LIVE_TERMINAL_GREEN;
    const uint32_t text_fg=LIVE_TERMINAL_FG;
#endif
    if(wb_mirror_active()){
        unsigned r=wb_mirror_cursor_row(),rows=wb_type_rows(style);
        if(r>=rows)r=rows-1;
        y=MIR_Y+r*wb_type_cell_h(style);
        if(y+WB_XFER_STRIP_H>MIR_END)y=MIR_END-WB_XFER_STRIP_H;
    }
    const unsigned fill=(unsigned)((uint64_t)W*(m->pct>100u?100u:m->pct)/100u);
    for(unsigned dy=0;dy<WB_XFER_STRIP_H;dy++)
        for(unsigned x=0;x<W;x++)p[(y+dy)*PITCH+x]=dy<17?card_bg:
            x<fill?bar_fill:bar_track;
    for(unsigned k=0;m->text[k] && k<sizeof m->text-1;k++){
        const unsigned x=4+k*12;
        if(x+10>W)break;
        const uint8_t *g=mirror_glyph(m->text[k]); /* includes the real '%' glyph */
        if(!g)continue;
        for(unsigned j=0;j<7;j++)for(unsigned i=0;i<5;i++)if(g[j]&(1u<<(4-i))){
            uint32_t *px=p+(y+1+j*2)*PITCH+x+2*i;
            px[0]=px[1]=px[PITCH]=px[PITCH+1]=text_fg;
        }
    }
}
