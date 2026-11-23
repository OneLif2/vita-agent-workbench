#include "wb_shell_channel.h"
#include "wb_game_io.h"
#include "wb_game_vita.h"
#include "wb_screen_mirror.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static wb_game_io g;
static wb_shell_channel sh;
static char wire[16000],oled[16000];
static unsigned nw,no,begins,cmds;
static int ack,can_start,fail_write,overreport;
static unsigned cols,rows,geo_calls;
static char previous[16000];
static const char *input="";
static void add(char *p,unsigned *n,const uint8_t *x,size_t k){
    assert(*n+k<16000);memcpy(p+*n,x,k);*n+=(unsigned)k;p[*n]=0;
}
void wb_mirror_begin(void){++begins;no=0;oled[0]=0;}
void wb_mirror_geometry(unsigned c,unsigned r){++geo_calls;cols=c;rows=r;}
void wb_mirror_write(const uint8_t *s,size_t k){assert(begins);add(oled,&no,s,k);}
const char *wb_gv_start(const char *cwd,bool tty,const char *cmd,const uint8_t *p,size_t n,int lf,uint64_t *owner){
    if(!can_start||strcmp(cwd,"ux0:/VITA-POC"))return "ERR game denied\n";
    wbg_init(&g);assert(wbg_start(&g,37,cmd,WBG_SCRIPT_SHA,1,tty));assert(wbg_prefeed(&g,37,p,n,lf)==1);
    *owner=37;return NULL;
}
int wb_gv_tick(uint64_t o,void *io,wbg_read_fn r,wbg_write_fn w){return wbg_tick(&g,o,1,io,r,w);}
static int rd(void *io,uint8_t *p,size_t n){(void)io;size_t k=strlen(input);if(k>n)k=n;memcpy(p,input,k);input+=k;return (int)k;}
static int wr(void *io,const uint8_t *p,size_t n){(void)io;if(fail_write)return -1;if(overreport)return (int)n+1;if((size_t)ack<n)n=(size_t)ack;add(wire,&nw,p,n);return (int)n;}
static int dir(void *io,const char *p,wb_out *out){(void)io;(void)out;return strcmp(p,"ux0:/VITA-POC")!=0;}
static int cat(void *io,const char *p,wb_out *out){(void)io;(void)p;return wb_out_puts(out,"FILE_PRIVATE_TOKEN_042\n");}
static int list(void *io,const char *p,bool ll,wb_out *out){(void)io;(void)p;(void)ll;return wb_out_puts(out,"test.txt\n");}
static int tick(void){wb_shell_ops ops={.isdir=dir,.cat=cat,.list=list};return wb_sh_pump(&sh,0,rd,wr,&ops,&cmds);}

static void idle(int n){for(int j=0;j<n;j++){assert(tick()==1);if(sh.mirror_started)assert(no==nw&&!memcmp(oled,wire,nw));}}
static void cmd(const char *c){input=c;idle(700);}
static void blank(int tty){
    unsigned starts=begins,geos=geo_calls;strcpy(previous,oled);
    nw=0;wire[0]=0;input="";ack=0;fail_write=0;overreport=0;can_start=0;
    assert(wb_sh_start(&sh,tty)==0);wb_sh_set_geometry(&sh,123,44);
    idle(4);assert(begins==starts && geo_calls==geos && !strcmp(oled,previous));
    ack=1;idle(1);assert(begins==starts+1 && geo_calls==geos+1 && cols==123 && rows==44);
    assert(nw==1 && no==1 && wire[0]=='V');
    idle(100);assert(strstr(oled,"VITA AGENT TERMINAL")&&strstr(oled,"ux0:/> "));
    wb_sh_set_geometry(&sh,77,21);assert(geo_calls==geos+2 && cols==77 && rows==21);
}
static void editor(int tty){
    blank(tty);
    cmd("pwd\r");assert(strstr(oled,"ux0:/\r\n"));
    cmd("cd VITA-POC\r");assert(strstr(oled,"ux0:/VITA-POC> "));
    cmd("ls -l\r");assert(strstr(oled,"test.txt\r\n"));
    cmd("cat test.txt\r");assert(strstr(oled,"FILE_PRIVATE_TOKEN_042\r\n")); /* deliberately displayed owner text */
    cmd("pwx\bd\r");assert((strstr(oled,"pwx\b \bd\r\n")!=NULL)==!!tty);
    cmd("bogus\r");assert(strstr(oled,"ERR "));
    cmd(WBG_COMMAND "\r");assert(strstr(oled,"ERR game denied"));
    assert((strstr(oled,"cat test.txt")!=NULL)==!!tty);
    input="exit\r";int rc=1;for(unsigned i=0;i<100&&rc==1;i++)rc=tick();
    assert(!rc && !memcmp(oled,wire,nw) && no==nw && strstr(oled,"Bye.\r\n"));
}
static void game(int tty){
    blank(tty);unsigned starts=begins;
    cmd("cd VITA-POC\r");can_start=1;cmd(WBG_COMMAND "\r");
    assert(sh.game_owner && begins==starts && strstr(oled,"Type help for commands.") && strstr(oled,"PYTHON runtime="));
    static const char text[]="| X |   | O |\n\xe2\x99\xa5 move: ";
    size_t mark=no;assert(wbg_write(&g,(const uint8_t*)text,sizeof text-1)==1);
    ack=0;idle(10);assert(no==mark);ack=1;idle(100);
    assert(!strcmp(oled+mark,"| X |   | O |\r\n\xe2\x99\xa5 move: "));
    char line[WBG_LINE+1];assert(wbg_readline(&g,line)==0);mark=no;
    cmd("a");assert(!strcmp(oled+mark,tty?"a":"")); /* before pressing ENTER */
    cmd("b\b1\r");assert(wbg_readline(&g,line)==1&&!strcmp(line,"a1"));
    assert(!strcmp(oled+mark,tty?"ab\b \b1\r\n":"")); /* no separate game masking or double echo */
    wbg_finish(&g,1);assert(tick()==0);assert(begins==starts);
}
int main(void){
    editor(1);editor(0);game(1);game(0);blank(1);
    size_t seen=no;input="p";ack=0;idle(4);assert(no==seen);fail_write=1;assert(tick()==-1&&no==seen);
    fail_write=0;overreport=1;assert(tick()==-1&&no==seen);
    puts("PASS shared session from first ACK: PTY/no-PTY banner, cwd, ls/cat text, per-key echo/backspace, denial, EOF/Bye, game UTF-8 and uncensored rendered echo; exact across short/would-block/error writes, session separation, initial/live geometry.");
    return 0;
}
