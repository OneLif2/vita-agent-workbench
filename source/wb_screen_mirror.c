#include "wb_screen_mirror.h"
#include "wb_panel_geometry.h"
#include <string.h>
struct line {char cells[WB_MIRROR_MAX_COLS+1];unsigned len;bool soft;};
struct grid {struct line row[WB_MIRROR_MAX_ROWS];unsigned w,h,x,y,first,scrolled;};
static struct grid grids[2];
static unsigned which,utf_left,utf_val,utf_min,escape;
static bool active;
/* Only committed, rendered characters are retained. Visual rows keep their
 * original wrap width once evicted; the live viewport still reflows normally. */
struct saved_line {uint16_t len;char cells[WB_MIRROR_MAX_COLS+1];};
static struct saved_line hist[WB_MIRROR_HISTORY_ROWS];
static unsigned oldest,count,anchor,pan_col;
static bool browsing,panned;
static uint64_t revision;
static wb_type_style local_style={WB_TYPE_CLASSIC,2,2,6};
wb_type_style wb_type_get(void){return local_style;}
bool wb_type_set(wb_type_style s){
    if(!wb_type_valid(s))return false;
    if(s.family!=local_style.family || s.scale!=local_style.scale ||
       s.gap_x!=local_style.gap_x || s.gap_y!=local_style.gap_y){
        local_style=s;
        /* Both framebuffer caches use this revision; no change to PTY,
         * history, anchored scroll position, input or remote geometry. */
        ++revision;
    }
    return true;
}
#define G (grids[which])
static struct line *at(struct grid *g,unsigned y){return &g->row[(g->first+y)%g->h];}
static void init(struct grid *g,unsigned w,unsigned h){memset(g,0,sizeof *g);g->w=w;g->h=h;}
static void follow(void){browsing=panned=false;anchor=pan_col=0;}
void wb_mirror_reset(void){
    memset(grids,0,sizeof grids);memset(hist,0,sizeof hist);oldest=count=0;follow();
    active=false;which=0;utf_left=utf_min=utf_val=escape=0;revision++;
}
void wb_mirror_begin(void){wb_mirror_reset();init(&G,WB_MIRROR_COLS,WB_MIRROR_ROWS);active=true;}
bool wb_mirror_active(void){return active;}
unsigned wb_mirror_cols(void){return G.w;}
unsigned wb_mirror_rows(void){return G.h;}
unsigned wb_mirror_cursor_row(void){return G.y;}
unsigned wb_mirror_cursor_col(void){return G.x;}
const char *wb_mirror_row(unsigned y){return y<G.h?at(&G,y)->cells:"";}
uint64_t wb_mirror_revision(void){return revision;}
bool wb_mirror_browsing(void){return browsing;}
/* Combined index: [0,count) history; [count,count+G.h) live rows. */
static unsigned live_top(unsigned n){return count+(G.y>=n?G.y+1-n:0);}
static unsigned view_top(unsigned n){
    unsigned bottom=live_top(n);
    return browsing&&anchor<bottom?anchor:bottom;
}
unsigned wb_mirror_scroll_offset(unsigned n){return active&&n?live_top(n)-view_top(n):0;}
static const struct saved_line *saved(unsigned pos){return &hist[(oldest+pos)%WB_MIRROR_HISTORY_ROWS];}
const char *wb_mirror_view_row(unsigned row,unsigned n){
    if(!active||!n||row>=n)return "";
    unsigned top=view_top(n);
    if(row>=count+G.h-top)return "";
    unsigned idx=top+row;
    return idx<count?saved(idx)->cells:wb_mirror_row(idx-count);
}
void wb_mirror_follow(void){if(browsing||panned){follow();revision++;}}
/* Saturate any int delta, including INT_MIN, without signed negation/overflow. */
static unsigned step(unsigned p,unsigned limit,unsigned delta,bool increase){
    return increase?p+(delta>limit-p?limit-p:delta):p-(delta>p?p:delta);
}
bool wb_mirror_scroll(int lines,unsigned n){
    if(!active||!n||!lines)return false;
    unsigned bottom=live_top(n),now=view_top(n);
    unsigned to=step(now,bottom,lines<0?0u-(unsigned)lines:(unsigned)lines,lines<0);
    if(to==bottom&&lines<0){
        bool changed=browsing||panned;
        wb_mirror_follow();return changed;
    }
    if(to==now)return false;
    if(!browsing){pan_col=0;panned=false;}
    browsing=true;anchor=to;revision++;return true;
}
static unsigned pan_limit(unsigned cols){
    unsigned width=G.w;
    if(browsing)for(unsigned i=0;i<count;i++){unsigned len=saved(i)->len;if(len>width)width=len;}
    return width>cols?width-cols:0;
}
unsigned wb_mirror_left(unsigned n){
    if(!active||!n)return 0;
    if(panned){unsigned lim=pan_limit(n);return pan_col<lim?pan_col:lim;}
    if(browsing)return 0;
    unsigned x=G.x<G.w?G.x:G.w-1;
    return x<n?0:x+1-n;
}
bool wb_mirror_pan(int cols,unsigned n){
    if(!active||!n||!cols)return false;
    unsigned now=wb_mirror_left(n);
    unsigned to=step(now,pan_limit(n),cols<0?0u-(unsigned)cols:(unsigned)cols,cols>0);
    if(now==to)return false;
    panned=true;pan_col=to;revision++;return true;
}
static void remember(const struct line *l){
    unsigned dest=(oldest+count)%WB_MIRROR_HISTORY_ROWS;
    if(count==WB_MIRROR_HISTORY_ROWS){
        oldest=(oldest+1)%WB_MIRROR_HISTORY_ROWS;
        if(browsing&&anchor)--anchor; /* keep the same text until it too expires */
    }else ++count;
    hist[dest].len=(uint16_t)l->len;memcpy(hist[dest].cells,l->cells,l->len+1);
}
static void next(struct grid *g,bool soft){
    if(g->y+1<g->h)g->y++;
    else{remember(at(g,0));g->first=(g->first+1)%g->h;g->scrolled++;memset(at(g,g->y),0,sizeof(struct line));}
    at(g,g->y)->soft=soft;
}
static void put(struct grid *g,char c){
    if(g->x>=g->w){next(g,true);g->x=0;} /* pending wrap */
    struct line *l=at(g,g->y);
    while(l->len<g->x)l->cells[l->len++]=' ';
    l->cells[g->x++]=c;
    if(l->len<g->x){l->len=g->x;l->cells[l->len]=0;}
}
void wb_mirror_geometry(unsigned w,unsigned h){
    if(!active)return;
    if(!w||!h){w=WB_MIRROR_COLS;h=WB_MIRROR_ROWS;}
    if(w>WB_MIRROR_MAX_COLS)w=WB_MIRROR_MAX_COLS;
    if(h>WB_MIRROR_MAX_ROWS)h=WB_MIRROR_MAX_ROWS;
    if(w==G.w&&h==G.h)return;
    /* Resizing resumes live follow, keeping prior saved visual rows at their
     * old widths. Any rows pushed off by reflow join history in order. */
    follow();revision++;
    struct grid *old=&G,*to=&grids[which^1];init(to,w,h);
    unsigned ay=0,ax=0,last=old->y;
    for(unsigned y=old->y+1;y<old->h;y++)if(at(old,y)->len)last=y;
    for(unsigned y=0;y<=last;y++){
        struct line *l=at(old,y);
        if(y && !l->soft){next(to,false);to->x=0;}
        unsigned len=l->len;if(y==old->y&&len<old->x)len=old->x;
        for(unsigned x=0;x<=len;x++){
            if(y==old->y&&x==old->x){ax=to->x;ay=to->y+to->scrolled;}
            if(x<len)put(to,x<l->len?l->cells[x]:' ');
        }
    }
    to->y=ay>to->scrolled?ay-to->scrolled:0;
    if(to->y>=h)to->y=h-1;
    to->x=ax;which^=1;
    memset(old,0,sizeof *old);
}
enum {ESC_NONE,ESC_INTRO,ESC_CSI,ESC_STRING,ESC_STRING_END};
static void consume(unsigned b){
    if(escape){
        if(escape==ESC_INTRO){
            escape=b=='['?ESC_CSI:(b==']'||b=='P'||b=='^'||b=='_')?ESC_STRING:ESC_NONE;
        }else if(escape==ESC_CSI){if((b>=0x40&&b<=0x7e)||b<0x20)escape=ESC_NONE;}
        else if(escape==ESC_STRING){if(b==7)escape=ESC_NONE;else if(b==27)escape=ESC_STRING_END;}
        else escape=b=='\\'||b==7?ESC_NONE:ESC_STRING;
        return;
    }
    if(utf_left){
        if((b&0xc0)==0x80){
            utf_val=(utf_val<<6)|(b&63);if(--utf_left)return;
            put(&G,utf_val==0x2665 && utf_min<=0x2665 ? WB_MIRROR_HEART:'?');return;
        }
        utf_left=0;put(&G,'?');
    }
    if(b>=0xc2&&b<=0xf4){utf_left=b<0xe0?1:b<0xf0?2:3;
        utf_min=utf_left==1?128:utf_left==2?2048:65536;
        utf_val=b&(utf_left==1?31u:utf_left==2?15u:7u);return;}
    if(b==27){escape=ESC_INTRO;return;}
    if(b=='\r'){G.x=0;return;}
    if(b=='\n'){if(G.x==G.w)G.x=G.w-1;next(&G,false);return;}
    if(b=='\b'){if(G.x)G.x--;return;}
    if(b=='\t'){unsigned x=(G.x/8+1)*8;G.x=x<G.w?x:G.w-1;return;}
    if(b>=32&&b<=126)put(&G,(char)b);else if(b>=128)put(&G,'?');
}
void wb_mirror_write(const uint8_t *p,size_t n){if(active&&p&&n){while(n--)consume(*p++);revision++;}}
