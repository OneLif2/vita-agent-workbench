/* Compare old/new live grid projection after reproducible UTF8/escape/control/
 * ASCII/wrap/resize and session transitions; never calls the new view APIs. */
#include "wb_screen_mirror.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
static uint32_t seed=0x01234567;
static uint32_t rnd(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
static uint64_t hash=UINT64_C(14695981039346656037);
static void add(unsigned x){hash=(hash^(uint64_t)x)*UINT64_C(1099511628211);}
int main(void){
    static const unsigned char *const tokens[]={
        (const unsigned char*)"A\r\n", (const unsigned char*)"\t", (const unsigned char*)"\b",
        (const unsigned char*)"pQRSTUVWXYZ0123456789", (const unsigned char*)"\rreplaced",
        (const unsigned char*)"\x1b[31m\x1b[0m",(const unsigned char*)"\x1b]xx\a",
        (const unsigned char*)"\xe2\x99\xa5\n",(const unsigned char*)"\xff?\n",
        (const unsigned char*)"\xe2",(const unsigned char*)"\x99\xa5"};
    wb_mirror_begin();
    for(int k=0;k<5000;k++){
        uint32_t n=rnd();
        if(n%271==0)wb_mirror_begin();
        else if(n%13==0){unsigned w=rnd()%74u;unsigned h=rnd()%10u;wb_mirror_geometry(w,h);}
        else {const unsigned char *b=tokens[n%(sizeof tokens/sizeof tokens[0])];wb_mirror_write(b,strlen((const char*)b));}
        add(wb_mirror_active());add(wb_mirror_cols());add(wb_mirror_rows());
        add(wb_mirror_cursor_row());add(wb_mirror_cursor_col());
        for(unsigned r=0;r<wb_mirror_rows();r++){const unsigned char *b=(const unsigned char*)wb_mirror_row(r);
            for(;*b;b++){add(*b);}add(0);
        }
    }
    printf("live grid state stream (5000 operations): %016" PRIx64 "\n",hash);
}

