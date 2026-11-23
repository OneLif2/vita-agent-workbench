#include "wb_game.h"
#include <stdio.h>
#include <string.h>
static unsigned total_delay;static int read_(void *p,char *s,size_t n){(void)p;if(!fgets(s,(int)n,stdin))return -1;return (int)strcspn(s,"\r\n");}
static int write_(void *p,const char *s,size_t n){(void)p;return fwrite(s,1,n,stdout)==n?0:-1;}
static int delay_(void *p,unsigned n){(void)p;total_delay+=n;return 0;}
int main(void){int r=wb_game_run(NULL,read_,write_,delay_);fprintf(stderr,"VM: %s; rc=%d; requested_delay_ms=%u (HOST fixture does not sleep)\n",WB_GAME_RUNTIME,r,total_delay);return r?2:0;}
