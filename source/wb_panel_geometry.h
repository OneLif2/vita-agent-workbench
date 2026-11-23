#ifndef WB_PANEL_GEOMETRY_H
#define WB_PANEL_GEOMETRY_H
#include <stdbool.h>
/* Physical pixels only.  gap_x / gap_y are blank pixels added to the
 * scaled face's fixed glyph box, not point sizes or glyph translations. */
enum { WB_TYPE_CLASSIC=0, WB_TYPE_JETBRAINS=1,
       WB_TYPE_MIN_SCALE=1,WB_TYPE_MAX_SCALE=3,
       WB_TYPE_MAX_X=4,WB_TYPE_MIN_Y=2,WB_TYPE_MAX_Y=10,
       WB_PANEL_WIDTH_PX=960,WB_PANEL_BODY_PX=450,
       WB_TYPE_CLASSIC_W=5,WB_TYPE_CLASSIC_H=7,WB_TYPE_JB_W=8,WB_TYPE_JB_H=14 };
typedef struct {unsigned family,scale,gap_x,gap_y;} wb_type_style;
#define WB_TYPE_DEFAULT ((wb_type_style){WB_TYPE_CLASSIC,2,2,6})
static inline bool wb_type_valid(wb_type_style s){
    return s.family<=WB_TYPE_JETBRAINS && s.scale>=WB_TYPE_MIN_SCALE && s.scale<=WB_TYPE_MAX_SCALE &&
           s.gap_x<=WB_TYPE_MAX_X && s.gap_y>=WB_TYPE_MIN_Y && s.gap_y<=WB_TYPE_MAX_Y;
}
static inline wb_type_style wb_type_safe(wb_type_style s){return wb_type_valid(s)?s:WB_TYPE_DEFAULT;}
static inline unsigned wb_type_glyph_w(wb_type_style s){return s.family==WB_TYPE_JETBRAINS?WB_TYPE_JB_W:WB_TYPE_CLASSIC_W;}
static inline unsigned wb_type_glyph_h(wb_type_style s){return s.family==WB_TYPE_JETBRAINS?WB_TYPE_JB_H:WB_TYPE_CLASSIC_H;}
static inline unsigned wb_type_cell_w(wb_type_style s){s=wb_type_safe(s);return wb_type_glyph_w(s)*s.scale+s.gap_x;}
static inline unsigned wb_type_cell_h(wb_type_style s){s=wb_type_safe(s);return wb_type_glyph_h(s)*s.scale+s.gap_y;}
static inline unsigned wb_type_cols(wb_type_style s){return WB_PANEL_WIDTH_PX/wb_type_cell_w(s);}
static inline unsigned wb_type_rows(wb_type_style s){return WB_PANEL_BODY_PX/wb_type_cell_h(s);}
/* State is shared with the single-threaded mirror, not duplicated per translation unit. */
wb_type_style wb_type_get(void);
bool wb_type_set(wb_type_style s);
#define WB_PANEL_ROWS (wb_type_rows(wb_type_get()))
#define WB_PANEL_COLS (wb_type_cols(wb_type_get()))
#endif
