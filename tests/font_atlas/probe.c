/* Test the precise compiled API and license without filesystem or network dependencies on the Vita. */
#include <stdio.h>
#include <string.h>
#include "wb_font_jetbrains.h"
#include "wb_jetbrains_license.h"
int main(int argc, char **argv){
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"wb");if(!f)return 3;
    if(fwrite(wb_jb_license,1,sizeof(wb_jb_license)-1,f)!=sizeof(wb_jb_license)-1||fclose(f))return 4;
    if(WB_JB_WIDTH!=8||WB_JB_HEIGHT!=14||sizeof(wb_jb_atlas)!=1344||sizeof(wb_jb_license)-1!=4399)return 5;
    for(unsigned c=0;c<256;c++){
        const uint8_t *g=wb_jb_glyph((unsigned char)c);
        if(c<32||c>127){if(g||wb_jb_row((unsigned char)c,0))return 6;continue;}
        unsigned lit=0;
        if(!g||wb_jb_row((unsigned char)c,14))return 7;
        for(unsigned y=0;y<14;y++){if(g[y]!=wb_jb_row((unsigned char)c,y))return 8;lit|=g[y];}
        if((lit!=0)!=(c!=32))return 9;
        for(unsigned k=32;k<c;k++)if(memcmp(g,wb_jb_glyph((unsigned char)k),14)==0)return 10;
    }
    puts("PASS 95 distinct printable ASCII + separate WB heart; 160 invalid codes safe; cell=8x14, atlas=1344, license=4399 bytes");
    return 0;
}
