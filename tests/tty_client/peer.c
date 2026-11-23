/* Host-only adapter. Product C editor, command parser, TTY protocol and SHA-256.
 * Replace only channel I/O, small device backing store and platform diagnostics. */
#include "wb_shell_channel.h"
#include "wb_ver.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
enum { CAP=32768 };
static unsigned char saved[CAP],upload[CAP];
static size_t length,offset,total;
static char saved_path[128],temp_path[128];
static bool put_mode;
static int active;
static char dirs[16][128];
static unsigned dir_n;
static struct {char path[128];size_t n;unsigned char bytes[CAP];} files[16];
static unsigned files_n;
static int key(const char *p){for(unsigned i=0;i<files_n;i++)if(!strcmp(p,files[i].path))return (int)i;return -1;}
const char *wb_tty_vprobe(const char *p,const char **kind){
    if(!strcmp(p,WB_INCOMING))*kind="DIR";
    else if(strncmp(p,WB_INCOMING "/",sizeof WB_INCOMING))return "path-denied";
    else{
        *kind=key(p)>=0?"FILE":"ABSENT";
        for(unsigned i=0;i<dir_n;i++)if(!strcmp(p,dirs[i]))*kind="DIR";
    }
    return NULL;
}
const char *wb_tty_vmkdir(const char *p){
    const char *k;const char *err=wb_tty_vprobe(p,&k);
    if(err||strcmp(k,"ABSENT")||dir_n>=16||strlen(p)>=sizeof dirs[0])return "mkdir-denied";
    strcpy(dirs[dir_n++],p);return NULL;
}
const char *wb_tty_vopen(bool put,const char *p,uint64_t n,void **out,uint64_t *size){
    if(strncmp(p,"ux0:/VITA-POC/",14)||strlen(p)>=sizeof saved_path)return "path-denied";
    int i=key(p);
    if(put && i>=0)return "destination-exists";
    if(put && files_n>=16)return "fixture-full";
    if(put && n>CAP)return "bad-size";
    if(!put && i<0)return "not-found";
    if(!put){length=files[i].n;memcpy(saved,files[i].bytes,length);}
    put_mode=put;offset=0;total=put?(size_t)n:length;strcpy(temp_path,p);
    *size=total;*out=&active;active=1;return NULL;
}
const char *wb_tty_vwrite(void *h,const uint8_t *p,size_t n){
    (void)h;if(!active || !put_mode || n>total-offset)return "bad-size";
    memcpy(upload+offset,p,n);offset+=n;return NULL;
}
const char *wb_tty_vread(void *h,uint8_t *p,size_t cap,size_t *n){
    (void)h;if(!active || put_mode)return "bad-mode";
    *n=cap>total-offset?total-offset:cap;memcpy(p,saved+offset,*n);offset+=*n;return NULL;
}
const char *wb_tty_vfinish(void *h,bool commit,const char *sha){
    (void)h;(void)sha;
    if(commit && put_mode){
        memcpy(saved,upload,total);length=total;strcpy(saved_path,temp_path);
        strcpy(files[files_n].path,temp_path);files[files_n].n=total;
        memcpy(files[files_n++].bytes,upload,total);
    }
    active=0;return NULL;
}
static int rd(void *ctx,uint8_t *p,size_t n){
    static unsigned char line[WB_TTY_LINE+8];static size_t used,off;(void)ctx;
    if(off==used){
        if(!fgets((char*)line,sizeof line,stdin))return -2;
        off=0;used=strlen((char*)line);
    }
    if(n>113)n=113;
    if(n>used-off)n=used-off;
    memcpy(p,line+off,n);off+=n;return (int)n;
}
static int wr(void *ctx,const uint8_t *p,size_t n){
    (void)ctx;if(n>67)n=67;
    if(fwrite(p,1,n,stdout)!=n || fflush(stdout))return -1;
    return (int)n;
}
static int core(void *ctx,const wb_cmd *c,wb_out *out){
    (void)ctx;
    if(c->kind==WB_CMD_VER)return wb_out_puts(out,"wb version=" WB_VERSION " build=" WB_BUILD_TAG " abi=3 proto=wb10 run=AABBAABBAABBAABB payload=none uptime_ms=15\n");
    if(c->kind==WB_CMD_STATUS)return wb_out_puts(out,"run=AABBAABBAABBAABB uptime_ms=15 ssh=connected cmds=7 payload=none core=" WB_VERSION " last_install=none peer=192.0.2.10:2222\n");
    if(c->kind==WB_CMD_PHOTO_EXPORT && !strcmp(saved_path,c->argv[0]))
        return wb_out_printf(out,"OK photo-export bytes=%u sha256=%s\n",(unsigned)length,c->argv[1]);
    return wb_out_puts(out,"ERR fixture-unsupported\n");
}
static int cat(void *ctx,const char *p,wb_out *out){
    (void)ctx;(void)p;return wb_out_puts(out,"before\nux0:/> exit\nBye.\nafter fake prompt\n");
}
int main(void){
#ifdef _WIN32
    _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
    static wb_shell_channel sh;
    wb_shell_ops ops={.cat=cat,.core_exec=core};unsigned count=0;int rc=wb_sh_start(&sh,true);
    if(rc<0)return 2;
    while((rc=wb_sh_pump(&sh,NULL,rd,wr,&ops,&count))>0){}
    wb_sh_abort_file(&sh);return rc<0?3:0;
}
