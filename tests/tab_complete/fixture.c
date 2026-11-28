#include "wb_shell_channel.h"
#include "wb_game_vita.h"
#include "wb_game_io.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static wb_shell_channel s;
static unsigned commands,lists,games,ticks;
static size_t used;
static const char *input;
static char output[32768],last_cat[WB_SH_PATH];
static int corrupt,fails,absent;
static int read_io(void *ctx,uint8_t *p,size_t n){
    (void)ctx;(void)n;if(!*input)return 0;*p=(uint8_t)*input++;return 1; /* force packet splits */
}
static int write_io(void *ctx,const uint8_t *p,size_t n){
    (void)ctx;if(n>3)n=3;assert(used+n<sizeof output);
    memcpy(output+used,p,n);used+=n;output[used]=0;return (int)n;
}
static int dir(void *ctx,const char *p,wb_out *out){
    (void)ctx;if(!strcmp(p,"ux0:/")||!strcmp(p,"ux0:/VITA-POC")||!strcmp(p,"ux0:/VITA-POC/maps"))return 0;
    (void)wb_out_puts(out,"ERR private-directory-do-not-echo\n");return 1;
}
static int list(void *ctx,const char *p,bool detailed,wb_out *out){
    (void)ctx;assert(!detailed);++lists;
    if(!strcmp(p,"ux0:/"))return wb_out_puts(out,"VITA-POC/\ndata/\n");
    if(!strcmp(p,"ux0:/VITA-POC/maps"))return wb_out_puts(out,"town.txt\n");
    assert(!strcmp(p,"ux0:/VITA-POC"));
    if(corrupt)return wb_out_puts(out,"tictactoe_ai.py\nevil\033[2J\n");
    if(fails){assert(!wb_out_puts(out,"tictactoe_ai.py\n"));return 1;} /* discard even a partial valid match */
    if(!absent && wb_out_puts(out,"tic")!=0)return -1;
    if(!absent && wb_out_puts(out,"tactoe_ai.py\n")!=0)return -1;
    return wb_out_puts(out,"map-aaa.txt\nmap-abb.txt\nmaps/\ntwo words.txt\nother.py\n");
}
static int cat(void *ctx,const char *path,wb_out *out){(void)ctx;strcpy(last_cat,path);return wb_out_puts(out,"ok\n");}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){(void)ctx;(void)cmd;(void)out;assert(!"unexpected command dispatch");return -1;}
static const wb_shell_ops ops={NULL,dir,list,cat,core};
const char *wb_gv_start(const char *cwd,bool tty,const char *cmd,const uint8_t *tail,size_t n,int lf,uint64_t *owner){
    (void)tail;(void)n;(void)lf;assert(!strcmp(cwd,"ux0:/VITA-POC") && tty && !strcmp(cmd,WBG_COMMAND));
    ++games;*owner=7;return NULL;
}
int wb_gv_tick(uint64_t owner,void *io,int(*rd)(void*,uint8_t*,size_t),int(*wr)(void*,const uint8_t*,size_t)){
    uint8_t one;(void)wr;assert(owner==7);++ticks;rd(io,&one,1);return 1;
}
void wb_gv_stop(uint64_t owner){(void)owner;}
static void feed(const char *text){
    input=text;unsigned count=0;
    do {assert(++count<10000);assert(wb_sh_pump(&s,NULL,read_io,write_io,&ops,&commands)==1);}
    while(*input||s.queued||s.ri!=s.rn);
}
static void start(bool tty){assert(!wb_sh_start(&s,tty));used=0;output[0]=0;commands=0;feed("");}
static void expect(const char *p){assert(strlen(p)==s.used&&!memcmp(s.line,p,s.used));assert(!s.bad_line);}
static void tab(const char *text,const char *expected){feed("\025");feed(text);feed("\t");expect(expected);}
int main(void){
    start(true);
    tab("pw","pwd ");assert(!commands&&!lists);
    feed("\r");assert(commands==1&&strstr(output,"pwd \r\nux0:/\r\n"));
    tab("appl","apply-");tab("xxy","xxy");feed("\b\bz");expect("xz");
    tab("python3 tic","python3 tic");assert(!lists);
    tab("cd /in","cd /inbox/");feed("\r");assert(!strcmp(s.shell.cwd,"ux0:/VITA-POC"));
    puts("PASS command unique + common-prefix + no match; cd /inbox resolves with per-session cwd");
    tab("ls map-","ls map-a");tab("ls map-a","ls map-a");tab("cd ma","cd maps/");
    tab("ls -l maps/to","ls -l maps/town.txt");
    tab("cat two","cat \"two words.txt\"");feed("\r");assert(!strcmp(last_cat,"ux0:/VITA-POC/two words.txt"));
    tab("cat 'two","cat 'two words.txt'");tab("ls /inbox/maps/t","ls /inbox/maps/town.txt");
    puts("PASS real quoting and dispatch, directory-only and nested absolute/relative filename completion");
    unsigned before=lists;
    tab("cat /private/s","cat /private/s");tab("cat /inbox/../s","cat /inbox/../s");tab("pwd;cat t","pwd;cat t");
    assert(lists==before&&!strstr(output,"private-directory-do-not-echo"));
    corrupt=1;tab("ls tic","ls tic");corrupt=0;
    fails=1;tab("ls tic","ls tic");fails=0;
    absent=1;tab("python3 tic","python3 tic");absent=0;
    tab("python3 oth","python3 oth");assert(!strchr(output,27));
    /* 02.18: Ctrl-A/E/K/W/L are readline keys; Ctrl-B is still an invalid control. */
    feed("\025abc\002");before=lists;feed("\t");assert(s.bad_line&&lists==before);feed("\025");
    char longline[WB_SH_LINE];memset(longline,' ',sizeof longline-1);memcpy(longline+sizeof longline-3,"pw",2);longline[sizeof longline-1]=0;
    tab(longline,longline);
    puts("PASS denied path, traversal, injected/control/partial listings, unknown script, invalid/stretched lines");
    before=commands;tab("python3 tic","python3 tictactoe_ai.py");assert(before==commands&&!games);
    assert(strstr(output,"python3 tictactoe_ai.py"));feed("\r");assert(games==1&&commands==before+1);
    before=lists;feed("\t");assert(ticks&&lists==before&&s.used==0);
    start(true);assert(!strcmp(s.shell.cwd,"ux0:/"));
    start(false);feed("pw\t");assert(s.bad_line&&!commands);assert(!strstr(output,"pwd"));
    puts("PASS approved Python line unchanged until Enter; game input and new/PTy-less sessions isolated");
    return 0;
}
