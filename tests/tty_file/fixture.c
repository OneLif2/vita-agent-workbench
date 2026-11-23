#include "wb_shell_channel.h"
#include "wb_screen_mirror.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *valid_path="ux0:/VITA-POC/OK file.bin";
static unsigned char stored[8192],stage[8192],sample[4095];
static size_t size,pos;
static bool available,writing,opened,errorwrite,grow;
static int closed,committed,commands;
const char *wb_tty_vprobe(const char *p,const char **kind){if(strcmp(p,valid_path))return "path-denied";*kind=available?"FILE":"ABSENT";return NULL;}
const char *wb_tty_vmkdir(const char *p){(void)p;return "destination-exists";}
const char *wb_tty_vopen(bool put,const char *p,uint64_t expected,void **op,uint64_t *sz){
    assert(!opened);
    if(strcmp(p,valid_path))return "path-denied";
    if(put&&available)return "destination-exists";
    if(!put&&!available)return "not-found";
    if(expected>sizeof stage)return "no-space";
    opened=true;writing=put;pos=0;*op=&opened;*sz=put?expected:size;return NULL;
}
const char *wb_tty_vwrite(void *op,const uint8_t *buf,size_t n){
    assert(op==&opened&&opened&&writing&&pos+n<=sizeof stage);
    if(errorwrite)return "io-error";
    memcpy(stage+pos,buf,n);pos+=n;return NULL;
}
const char *wb_tty_vread(void *op,uint8_t *buf,size_t cap,size_t *n){
    assert(op==&opened&&opened&&!writing);
    size_t actual=size+(grow?1u:0u);
    *n=actual-pos<cap?actual-pos:cap;
    if(*n>997)*n=997; /* encourage short reads */
    memcpy(buf,stored+pos,*n);pos+=*n;return NULL;
}
const char *wb_tty_vfinish(void *op,bool commit,const char *sha){
    assert(op==&opened&&opened);++closed;
    if(commit&&writing){assert(sha&&strlen(sha)==64);memcpy(stored,stage,pos);size=pos;available=true;++committed;}
    opened=false;return NULL;
}
static wb_shell_channel sh;
static const char *input;static size_t wpos;static char wire[16384];
static int blockers,rdlimit;
static int rd(void *op,uint8_t *b,size_t n){
    (void)op;if(!*input)return 0;
    size_t rem=strlen(input);if(rem>n)rem=n;if(rem>(size_t)rdlimit)rem=(size_t)rdlimit;
    memcpy(b,input,rem);input+=rem;return (int)rem;
}
static int wr(void *op,const uint8_t *b,size_t n){
    (void)op;
    if((++blockers%6)==0)return 0;
    if(n>11)n=11;
    assert(n<sizeof wire-wpos);memcpy(wire+wpos,b,n);wpos+=n;wire[wpos]=0;return (int)n;
}
static const wb_shell_ops ops={0};
static const char *feed(const char *s){
    input=s;wpos=0;wire[0]=0;
    for(int i=0;i<20000;i++){
        unsigned count=0;
        int rc=wb_sh_pump(&sh,NULL,rd,wr,&ops,&count);commands+=(int)count;
        if(rc<0){assert(sh.file_fault&&sh.closing&&!sh.queued&&!opened);return wire;}
        if(!rc||(!*input&&!sh.queued&&sh.ri==sh.rn))return wire;
    }assert(0);return NULL;
}
static void start(int tty){wb_sh_abort_file(&sh);assert(wb_sh_start(&sh,tty)==0);feed("");}
static void expect(const char *needle){if(!strstr(wire,needle)){fprintf(stderr,"want %s in %s\n",needle,wire);abort();}}
static void syncstart(bool tty){start(tty);assert(!opened);}
static int mirror_contains(const char *s){for(unsigned i=0;i<wb_mirror_rows();i++)if(strstr(wb_mirror_row(i),s))return 1;return 0;}
static void hex(const unsigned char *p,size_t n,char *out){
    const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[i*2]=h[p[i]>>4];out[i*2+1]=h[p[i]&15];}out[2*n]=0;
}
static void digest(const unsigned char *p,size_t n,char out[65]){
    uint8_t d[32];wb_sha256 c;wb_sha256_init(&c);wb_sha256_update(&c,p,n);wb_sha256_final(&c,d);wb_sha_hex(d,sizeof d,out);
}
static char cmd[512],line[WB_TTY_REPLY+48],encoded[WB_TTY_CHUNK*2+1],sha[65];
static void put_begin(size_t n,const char *digest_){
    snprintf(cmd,sizeof cmd,"put \"%s\" %zu sha256=%s\r",valid_path,n,digest_);feed(cmd);
}
int main(void){
    rdlimit=77;syncstart(true);
    for(size_t i=0;i<sizeof sample;i++)sample[i]=(unsigned char)(i*29);
    digest(sample,sizeof sample,sha);put_begin(sizeof sample,sha);expect("TTY1 READY PUT 4095 2048\r\n");
    hex(sample,2048,encoded);snprintf(line,sizeof line,"D 0 %s\r\n",encoded);feed(line);assert(!strcmp(wire,"TTY1 ACK 2048\r\n"));
    assert(!mirror_contains("001d3a577491")&&!mirror_contains("TTY1 ACK"));
    hex(sample+2048,2047,encoded);snprintf(line,sizeof line,"D 2048 %s\n",encoded);feed(line);expect("TTY1 ACK 4095");
    assert(!available&&!committed);feed("END\r");expect("TTY1 OK PUT 4095 ");expect(sha);expect("ux0:/> ");
    assert(!opened&&available&&committed==1&&size==sizeof sample&&!memcmp(stored,sample,size));
    put_begin(sizeof sample,sha);expect("TTY1 ERR destination-exists");
    feed("get \"ux0:/VITA-POC/OK file.bin\"\r");expect("TTY1 READY GET 4095 2048");
    for(size_t off=0;off<size;){
        size_t n=size-off;if(n>997)n=997;snprintf(line,sizeof line,"NEXT %zu\n",off);feed(line);
        hex(sample+off,n,encoded);snprintf(line,sizeof line,"TTY1 DATA %zu %s\r\n",off,encoded);
        assert(!strcmp(wire,line));off+=n;assert(!mirror_contains("TTY1 DATA")&&!mirror_contains("001d3a577491"));
    }
    feed("END\n");expect("TTY1 OK GET 4095 ");expect(sha);assert(!opened&&mirror_contains("TTY1 OK GET"));
    feed("pwd\n");expect("ux0:/\r\nux0:/> ");
    puts("PASS opaque binary NUL/0xff/ESC multi-frame PUT and GET; real bytes and SHA match; partial reads/writes+would-block; private data not mirrored; one shell still usable");
    available=false;put_begin(sizeof sample,sha);expect("TTY1 READY");int c=commands;
    feed("D 1 00\npwd\n");expect("TTY1 ERR offset");assert(sh.closing&&!opened&&commands==c&&!available);
    {unsigned n=0;assert(wb_sh_pump(&sh,NULL,rd,wr,&ops,&n)<0&&!n);} /* nonzero SSH status */
    syncstart(true);put_begin(sizeof sample,sha);feed("D 0 0g\n");expect("TTY1 ERR bad-hex");assert(sh.closing&&!opened);
    syncstart(true);put_begin(1,sha);feed("D 0 00\n");feed("END\n");expect("TTY1 ERR sha256-mismatch");assert(!opened&&!available);
    syncstart(true);put_begin(sizeof sample,sha);feed("END\n");expect("TTY1 ERR partial");assert(!opened);
    syncstart(true);put_begin(1,sha);errorwrite=true;feed("D 0 ab\r");expect("TTY1 ERR io-error");errorwrite=false;assert(!opened);
    syncstart(true);put_begin(1,sha);feed("D 0 0000\r");expect("TTY1 ERR bad-chunk");assert(!opened);
    syncstart(true);put_begin(1,sha);memset(line,'a',sizeof line-2);line[sizeof line-2]='\n';line[sizeof line-1]=0;feed(line);expect("TTY1 ERR invalid-frame");assert(!opened);
    syncstart(true);put_begin(1,sha);feed("D 0 x\003");expect("TTY1 ERR cancelled");assert(!sh.closing&&!opened);feed("pwd\n");expect("ux0:/\r\n");
    put_begin(1,sha);feed("CANCEL\r");expect("TTY1 ERR cancelled");assert(!opened&&!sh.closing);
    put_begin(1,sha);feed("D 0 a");int before=closed;wb_sh_abort_file(&sh);wb_sh_abort_file(&sh);assert(closed==before+1&&!opened&&!available);
    puts("PASS no publish on wrong offset, digest, size, malformed hex, oversized frame or I/O error; no execution of trailing frame bytes; Ctrl-C/CANCEL/disconnect cleanup idempotent");
    syncstart(false);put_begin(1,sha);expect("TTY1 ERR pty-required");assert(!opened);syncstart(true);
    feed("get ux0:/data/INAP00018/secret\n");expect("TTY1 ERR path-denied");assert(!opened);
    feed("get C:/unsafe\n");expect("TTY1 ERR path-denied");assert(!opened);
    feed("tree-stat \"ux0:/VITA-POC/OK file.bin\"\n");expect("TTY1 OK ABSENT");
    feed("tree-mkdir \"ux0:/VITA-POC/OK file.bin\"\n");expect("TTY1 ERR destination-exists");
    put_begin(0,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");expect("TTY1 READY PUT 0");
    feed("END\n");expect("TTY1 OK PUT 0 e3b0c442");available=false;
    put_begin(201326593,sha);expect("TTY1 ERR bad-size");
    put_begin(5,"dead");expect("TTY1 ERR bad-sha256");put_begin(9000,sha);expect("TTY1 ERR no-space");assert(!opened);
    available=true;size=0;feed("get \"ux0:/VITA-POC/OK file.bin\"\n");expect("TTY1 READY GET 0");feed("END\n");expect("TTY1 OK GET 0 e3b0c44298fc1c149afbf4c8996fb924");
    feed("get \"ux0:/VITA-POC/OK file.bin\"\n");grow=true;feed("END\n");expect("TTY1 ERR size-changed");assert(!opened);
    puts("PASS PTY requirement, protected path, quota, digest syntax, destination refusal; empty GET and file-growth denial");
    return 0;
}
