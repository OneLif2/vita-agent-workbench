#include "wb_tty_file.h"
#include "wb_ver.h"
#include "wb_cmd.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

static const char *skip(const char *p){while(*p==' '||*p=='\t')p++;return p;}
static bool verb(const char *s,const char *v){
    size_t n=strlen(v);return !strncmp(s,v,n)&&(!s[n]||s[n]==' '||s[n]=='\t');
}
bool wb_tty_recognizes(const char *s){s=skip(s);return verb(s,"put")||verb(s,"send")||verb(s,"get");}
static int digit(unsigned char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static bool decimal(const char **p,uint64_t *n){
    const char *q=*p;uint64_t v=0;
    if(*q<'0'||*q>'9'||(*q=='0'&&q[1]>='0'&&q[1]<='9'))return false;
    while(*q>='0'&&*q<='9'){
        unsigned d=(unsigned)(*q++-'0');if(v>(UINT64_MAX-d)/10)return false;
        v=v*10+d;
    }
    *p=q;*n=v;return true;
}
static void failmsg(wb_tty_file *f,const char *why){
    snprintf(f->reply,sizeof f->reply,"TTY1 ERR %s\r\n",why);
}
bool wb_tty_tree_command(const char *line,bool pty,char *reply,size_t cap){
    const char *s=skip(line),*kind=NULL,*err=NULL;
    bool make=verb(s,"tree-mkdir");
    if(!make&&!verb(s,"tree-stat"))return false;
    while(*s&&*s!=' '&&*s!='\t')s++;
    s=skip(s);
    size_t n=strlen(s);
    char path[WB_CMD_ARG_MAX];
    if(!pty)err="pty-required";
    else if(n<3||s[0]!='"'||s[n-1]!='"'||n-2>=sizeof path)err="usage";
    else{
        memcpy(path,s+1,n-2);path[n-2]=0;
        if(make){err=wb_tty_vmkdir(path);kind="MKDIR";}
        else err=wb_tty_vprobe(path,&kind);
    }
    snprintf(reply,cap,err?"TTY1 ERR %s\r\n":"TTY1 OK %s\r\n",err?err:kind);
    return true;
}
void wb_tty_abort(wb_tty_file *f){
    if(f&&f->handle){wb_tty_vfinish(f->handle,false,NULL);f->handle=NULL;}
}
const char *wb_tty_begin(wb_tty_file *f,const char *line){
    memset(f,0,sizeof *f);
    const char *s=skip(line);f->put=!verb(s,"get");
    while(*s&&*s!=' '&&*s!='\t')s++;
    s=skip(s);char quote=0,path[WB_CMD_ARG_MAX];size_t count=0;
    if(*s=='"'||*s=='\'')quote=*s++;
    while(*s && (quote?*s!=quote:*s!=' '&&*s!='\t')){
        if(count==sizeof path-1||(unsigned char)*s<32||(unsigned char)*s>=127||
           (strchr("\\\":*?<>|`$;&'",*s) && !(*s==':' && count==3)))return "path-denied";
        path[count++]=*s++;
    }
    path[count]=0;
    if(quote && (!*s||*s++!=quote))return "syntax";
    if((*s&&*s!=' '&&*s!='\t')||strncmp(path,"ux0:/",5))return "path-denied";
    s=skip(s);uint64_t expected=0;
    if(f->put){
        if(!decimal(&s,&expected)||expected>WB_UPLOAD_MAX)return "bad-size";
        if(*s!=' '&&*s!='\t')return "usage";
        s=skip(s);if(strncmp(s,"sha256=",7)||strlen(s+7)!=64)return "bad-sha256";
        s+=7;for(int i=0;i<64;i++)if(digit((unsigned char)s[i])<0)return "bad-sha256";
        memcpy(f->expected,s,65);
    }else if(*s)return "usage";
    const char *e=wb_tty_vopen(f->put,path,expected,&f->handle,&f->size);
    if(!e&&(!f->handle||f->size>WB_UPLOAD_MAX||(f->put&&f->size!=expected)))e="size-or-open";
    if(e){wb_tty_abort(f);return e;}
    wb_sha256_init(&f->sha);
    snprintf(f->reply,sizeof f->reply,"TTY1 READY %s %" PRIu64 " %u\r\n",
             f->put?"PUT":"GET",f->size,(unsigned)WB_TTY_CHUNK);
    return NULL;
}
static int fail(wb_tty_file *f,const char *m){wb_tty_abort(f);failmsg(f,m);return -1;}
int wb_tty_frame(wb_tty_file *f,bool *priv){
    *priv=false;f->line[f->n]=0;const char *s=f->line;f->n=0;
    if(!strcmp(s,"CANCEL")){
        wb_tty_abort(f);failmsg(f,"cancelled");return 0;
    }
    if(!strcmp(s,"END")){
        if(f->offset!=f->size)return fail(f,"partial");
        if(!f->put){size_t extra=0;const char *e=wb_tty_vread(f->handle,f->raw,1,&extra);
            if(e||extra)return fail(f,e?e:"size-changed");}
        uint8_t digest[32];char hex[65];
        wb_sha256_final(&f->sha,digest);wb_sha_hex(digest,sizeof digest,hex);
        if(f->put&&strcmp(hex,f->expected))return fail(f,"sha256-mismatch");
        const char *e=wb_tty_vfinish(f->handle,true,hex);f->handle=NULL;
        if(e){failmsg(f,e);return -1;}
        snprintf(f->reply,sizeof f->reply,"TTY1 OK %s %" PRIu64 " %s\r\n",f->put?"PUT":"GET",f->size,hex);
        return 0;
    }
    uint64_t offset=0;size_t len=0;uint64_t left=f->size-f->offset;
    if(!left)return fail(f,"expected-end");
    if(f->put){
        if(strncmp(s,"D ",2))return fail(f,"bad-frame");
        s+=2;if(!decimal(&s,&offset)||*s++!=' '||offset!=f->offset)return fail(f,"offset");
        size_t z=strlen(s);len=z/2;
        if(!len||(z&1)||len>sizeof f->raw||len>left)return fail(f,"bad-chunk");
        for(size_t i=0;i<len;i++){
            int hi=digit((unsigned char)s[2*i]),lo=digit((unsigned char)s[2*i+1]);
            if(hi<0||lo<0)return fail(f,"bad-hex");
            f->raw[i]=(uint8_t)((hi<<4)|lo);
        }
        const char *e=wb_tty_vwrite(f->handle,f->raw,len);
        if(e)return fail(f,e);
        snprintf(f->reply,sizeof f->reply,"TTY1 ACK %" PRIu64 "\r\n",f->offset+len);
    }else{
        if(strncmp(s,"NEXT ",5))return fail(f,"bad-frame");
        s+=5;if(!decimal(&s,&offset)||*s||offset!=f->offset)return fail(f,"offset");
        size_t cap=left<sizeof f->raw?(size_t)left:sizeof f->raw;
        const char *e=wb_tty_vread(f->handle,f->raw,cap,&len);
        if(e||!len||len>cap)return fail(f,e?e:"partial");
        int o=snprintf(f->reply,sizeof f->reply,"TTY1 DATA %" PRIu64 " ",offset);
        static const char hex[]="0123456789abcdef";
        for(size_t i=0;i<len;i++){f->reply[o++]=hex[f->raw[i]>>4];f->reply[o++]=hex[f->raw[i]&15];}
        memcpy(f->reply+o,"\r\n",3);
    }
    wb_sha256_update(&f->sha,f->raw,len);f->offset+=len;*priv=true;return 1;
}
