#include "wb_shell_channel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static wb_shell_channel shell;
typedef struct {
    const unsigned char *input;size_t size,read,pos,rdcap,wrcap;
    char output[131072];unsigned ticks,commands,ls_count;
} stream;
static int input(void *ctx,uint8_t *dst,size_t n) {
    stream *s=ctx;
    if(s->read==s->size)return -2;
    if(n>s->size-s->read)n=s->size-s->read;
    if(n>s->rdcap)n=s->rdcap;
    memcpy(dst,s->input+s->read,n);s->read+=n;return (int)n;
}
static int output(void *ctx,const uint8_t *src,size_t n) {
    stream *s=ctx;
    if(s->ticks%4==0)return 0; /* backpressure */
    if(n>s->wrcap)n=s->wrcap;
    assert(s->pos+n<sizeof s->output);memcpy(s->output+s->pos,src,n);s->pos+=n;
    s->output[s->pos]=0;return (int)n;
}
static int dir(void *ctx,const char *p,wb_out *out){(void)ctx;(void)out;return strcmp(p,"ux0:/data")?1:0;}
static int ls(void *ctx,const char *p,bool lng,wb_out *out){
    stream *s=ctx;assert(!strcmp(p,"ux0:/data") && lng);s->ls_count++;return wb_out_puts(out,"file\n");
}
static int cat(void *ctx,const char *p,wb_out *out){
    (void)ctx;
    if(!strcmp(p,"ux0:/unsafe")) return wb_out_puts(out,"abc\033X\rZ\n");
    assert(!strcmp(p,"ux0:/over"));char pad[1024];memset(pad,'+',sizeof pad);
    for(unsigned i=0;i<32;i++){if(out->write(out->ctx,pad,sizeof pad)<0)return -1;}
    return 0;
}
static int core(void *ctx,const wb_cmd*c,wb_out*o){(void)ctx;(void)c;(void)o;abort();}
static stream test; /* avoid putting multiple large test fixtures on the stack */
static void play(const unsigned char *p,size_t n,bool tty,size_t rd,size_t wr){
    memset(&test,0,sizeof test);test.input=p;test.size=n;test.rdcap=rd;test.wrcap=wr;
    wb_shell_ops ops={&test,dir,ls,cat,core};
    assert(wb_sh_start(&shell,tty)==0);
    int rc=1;
    for(;rc>0 && test.ticks<100000;test.ticks++){
        unsigned c=0;
        rc=wb_sh_pump(&shell,&test,input,output,&ops,&c);
        assert(c<=1);test.commands+=c;
    }
    assert(rc==0);assert(!memchr(test.output,0,test.pos));
}
#define RUN(msg,pty,rd,wr) play((const unsigned char *)(msg),sizeof(msg)-1,pty,rd,wr)
int main(void){
    RUN("pwz\b" "d\r\ncd data\rls -l\nexit\r",true,3,4);
    assert(test.commands==4 && test.ls_count==1 && strstr(test.output,"\b \b"));
    assert(strstr(test.output,"ux0:/\r\n") && strstr(test.output,"ux0:/data> ") && strstr(test.output,"file\r\n") && strstr(test.output,"Bye.\r\n"));
    puts("PASS interactive PTY with backspace, CR/LF normalization, directory state, partial writes");
    RUN("p\033[Awd\nexit\n",false,1,2);
    assert(test.commands==2 && strstr(test.output,"ux0:/> ux0:/\r\n") && !strstr(test.output,"pwd"));
    puts("PASS no-PTY no input echo, navigation escapes split across packets");
    RUN("cd data\003pwd\nrm something\025pwd\nrm incomplete",true,5,7);
    assert(test.commands==2 && strstr(test.output,"^C\r\n") && strstr(test.output,"^U\r\n") && !strstr(test.output,"ux0:/data>"));
    puts("PASS Ctrl-C, Ctrl-U cancel without dispatch; partial EOF never executes");
    RUN("pw\000d\nexit\r",false,1,2);
    assert(test.commands==1 && strstr(test.output,"ERR invalid or long line\r\n"));
    unsigned char large[WB_SH_LINE+80];memset(large,'a',sizeof large);memcpy(large,"exit",4);
    memcpy(large+sizeof large-10,"\x7f\r\npwd\n\004XX",10);
    play(large,sizeof large,true,41,100);
    assert(test.commands==1 && strstr(test.output,"ERR invalid or long line\r\n") && strstr(test.output,"ux0:/\r\n"));
    puts("PASS NUL and overflow discard entire command; Ctrl-D closes cleanly");
    RUN("cat unsafe\ncat over\npwd\nexit\n",false,255,4096);
    assert(test.commands==4 && !strchr(test.output,'\033') && !strchr(test.output,'+') &&
           strstr(test.output,"abc?XZ\r\n") && strstr(test.output,"ERR output-limit\r\n"));
    puts("PASS terminal output sanitation and bounded-output failure; next command remains usable");
    return 0;
}
