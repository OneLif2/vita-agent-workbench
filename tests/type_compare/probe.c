/* Identical PTY text/size on both releases. Test only the physical display.
 * WB_CAN_STYLE is detected by the caller from the supported public API. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_screen_mirror.h"
#include "active_terminal.h"
enum {W=960,H=544,PITCH=1024};
#include "screen.inc"
#include "mirror_panel.inc"
static uint32_t pix[H*PITCH];
int main(int argc,char **argv){
 if(argc!=3)return 2;
 unsigned mode=(unsigned)strtoul(argv[1],NULL,10); if(mode>3)return 2;
 wb_mirror_begin();wb_mirror_geometry(132,40);
 int changed=0;
#if WB_CAN_STYLE
 wb_type_style p=WB_TYPE_DEFAULT;
 if(mode==1)p.gap_y=8;
 if(mode>=2){p.family=WB_TYPE_JETBRAINS;p.scale=(mode==2?1:2);}
 if(!wb_type_set(p))return 3;
 changed=mode!=0;
#endif
 const char *s="HH  terminal sample\r\nHH  0123456789 | Il1 O0 {} []\r\nHH  ux0:/> ls -l\r\nHH  main.py     2048 bytes";
 wb_mirror_write((const uint8_t*)s,strlen(s));
 for(unsigned i=0;i<H*PITCH;i++)pix[i]=LIVE_TERMINAL_BG;draw_mirror(pix,NULL,NULL,false);
 FILE *f=fopen(argv[2],"wb");if(!f)return 4;fprintf(f,"P6\n960 544\n255\n");for(unsigned y=0;y<H;y++)for(unsigned x=0;x<W;x++){uint32_t c=pix[y*PITCH+x];fputc(c&255,f);fputc((c>>8)&255,f);fputc((c>>16)&255,f);}if(fclose(f))return 5;
 printf("supported_request=%d PTY=%ux%u\n",changed,wb_mirror_cols(),wb_mirror_rows());return 0;
}
