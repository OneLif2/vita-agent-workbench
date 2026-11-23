/* Actual mirror engine; no platform/kernel, network, or mock output. */
#include "wb_screen_mirror.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
static void emit(const char *s){wb_mirror_write((const uint8_t*)s,strlen(s));}
static void hard(unsigned n){char s[16];snprintf(s,sizeof s,"L%03u\r\n",n);emit(s);}
static void row(unsigned n,unsigned h,const char *v){assert(!strcmp(wb_mirror_view_row(n,h),v));}
static void begin(unsigned w,unsigned h){wb_mirror_begin();wb_mirror_geometry(w,h);}
int main(void){
    wb_mirror_reset();
    assert(!wb_mirror_scroll(INT_MAX,25)&&!wb_mirror_pan(INT_MIN,80));
    row(0,25,"");row(UINT_MAX,UINT_MAX,"");
    begin(80,24);
    for(unsigned i=0;i<40;i++)hard(i);
    assert(!strcmp(wb_mirror_row(0),"L017"));row(0,25,"L017");
    unsigned y=wb_mirror_cursor_row(),x=wb_mirror_cursor_col();
    uint64_t rev=wb_mirror_revision();
    assert(wb_mirror_scroll(6,25)&&wb_mirror_browsing());row(0,25,"L011");
    assert(x==wb_mirror_cursor_col() && y==wb_mirror_cursor_row() && wb_mirror_revision()!=rev);
    for(unsigned i=40;i<60;i++)hard(i);
    row(0,25,"L011");assert(wb_mirror_scroll_offset(25)==26); /* pinned on output */
    assert(wb_mirror_scroll(INT_MAX,25));row(0,25,"L000");
    assert(!wb_mirror_scroll(INT_MAX,25));assert(wb_mirror_scroll_offset(25)==37);
    for(unsigned i=60;i<220;i++)hard(i);
    row(0,25,"L069");assert(wb_mirror_scroll_offset(25)==128); /* evicted; clamp to OLDEST */
    assert(wb_mirror_scroll(-127,25));row(0,25,"L196");
    assert(wb_mirror_scroll(-1,25)&&!wb_mirror_browsing());row(0,25,"L197");
    assert(!wb_mirror_scroll(INT_MIN,25));
    row(23,25,"");row(24,25,"");row(25,25,"");row(UINT_MAX,UINT_MAX,"");
    rev=wb_mirror_revision();wb_mirror_write(NULL,3);emit("");assert(wb_mirror_revision()==rev);

    /* DEEP PTY: rows still inside the live grid are browseable too. */
    begin(80,100);for(unsigned i=0;i<60;i++)hard(i);
    row(0,25,"L036");row(24,25,"");
    assert(wb_mirror_scroll(25,25));row(0,25,"L011");
    for(unsigned i=60;i<105;i++)hard(i);
    row(0,25,"L011");assert(wb_mirror_scroll_offset(25)==70);
    wb_mirror_follow();row(0,25,"L081");

    /* Wide live cursor follows automatically; browsing does NOT inherit the right edge. */
    char a[211];memset(a,'a',210);a[210]='\0';
    begin(220,4);emit(a);assert(wb_mirror_left(80)==131);
    assert(wb_mirror_pan(-10,80)&&wb_mirror_left(80)==121);
    wb_mirror_follow();assert(wb_mirror_left(80)==131);
    emit("\r\n");hard(1);hard(2);hard(3);hard(4);
    assert(wb_mirror_scroll(INT_MAX,25));row(0,25,a);assert(wb_mirror_left(80)==0);
    assert(wb_mirror_pan(INT_MAX,80)&&wb_mirror_left(80)==140);
    assert(!wb_mirror_pan(INT_MAX,80));assert(wb_mirror_pan(INT_MIN,80)&&wb_mirror_left(80)==0);
    wb_mirror_geometry(40,4);assert(!wb_mirror_browsing()&&wb_mirror_left(80)==0);
    assert(wb_mirror_scroll(INT_MAX,25));row(0,25,a);assert(wb_mirror_pan(INT_MAX,80));
    assert(wb_mirror_left(80)==130); /* old width textual content retained in history */
    assert(wb_mirror_scroll(INT_MIN,25)&&wb_mirror_left(80)==0);
    wb_mirror_begin();row(0,25,"");assert(!wb_mirror_scroll(INT_MAX,25));assert(!wb_mirror_browsing());
    /* Reflow which evicts portions of still-live rows archives them in order. */
    begin(10,3);emit("ABCDEFGHIJ\r\nklmnopqrst\r\nuvw");
    wb_mirror_geometry(5,2);
    assert(wb_mirror_scroll(INT_MAX,2));row(0,2,"ABCDE");row(1,2,"FGHIJ");
    assert(wb_mirror_scroll(-1,2));row(0,2,"FGHIJ");row(1,2,"klmno");
    wb_mirror_follow();row(0,2,"pqrst");row(1,2,"uvw");
    wb_mirror_reset();assert(wb_mirror_rows()==0);row(0,25,"");wb_mirror_write((const uint8_t*)"private",7);row(0,25,"");
    puts("PASS history: 128 evicted rows, live/anchored selection, eviction clamping, tall and wide PTYs, bounded horizontal pan, resize/reflow, session clearing, epoch & extreme inputs.");
}
