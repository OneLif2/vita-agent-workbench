#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("O3")
#endif
#include "wb_transfer_limits.h"
/* SSH File Transfer Protocol v3 (draft-ietf-secsh-filexfer-02), incoming-only.
 * No shell delegation, overwrites, symbolic links, extension negotiation or
 * native paths. All file/directory descriptors are private to one channel. */
#include "wb_sftp_ro.h"
#include "wb_ver.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum { INIT=1,VERSION=2,OPEN=3,CLOSE=4,READ=5,WRITE=6,LSTAT=7,FSTAT=8,
       SETSTAT=9,FSETSTAT=10,OPENDIR=11,READDIR=12,REMOVE=13,MKDIR=14,
       RMDIR=15,REALPATH=16,STAT=17,RENAME=18,SYMLINK=20,
       STATUS=101,HANDLE=102,DATA=103,NAME=104,ATTRS=105 };
typedef struct {const uint8_t *p;size_t n;int bad;} reader;
typedef struct {uint8_t *p;size_t n,cap;int bad;} writer;
typedef struct {const uint8_t *s;size_t n;} span;
static uint32_t num32(const uint8_t *p){
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static uint32_t u32(reader *r){
    if(r->n<4){r->bad=1;return 0;} uint32_t v=num32(r->p);r->p+=4;r->n-=4;return v;
}
static span string(reader *r){
    size_t n=u32(r);
    if(r->bad||n>r->n){r->bad=1;return (span){NULL,0};}
    span a={r->p,n};r->p+=n;r->n-=n;return a;
}
static int done(const reader *r){return !r->bad&&!r->n;}
static void raw(writer *w,const void *p,size_t n){
    if(n>w->cap-w->n){w->bad=1;return;}if(n)memcpy(w->p+w->n,p,n);w->n+=n;
}
static void byte(writer *w,unsigned v){uint8_t t=(uint8_t)v;raw(w,&t,1);}
static void put32(writer *w,uint32_t v){
    uint8_t a[4]={(uint8_t)(v>>24),(uint8_t)(v>>16),(uint8_t)(v>>8),(uint8_t)v};raw(w,a,4);
}
static void str(writer *w,const char *p){size_t n=strlen(p);put32(w,(uint32_t)n);raw(w,p,n);}
static void msg(writer *w,unsigned type,uint32_t id){byte(w,type);put32(w,id);}
static void attrs(writer *w,const wb_sftp_attr *a){
    /* Vita does not provide a reliable access time through our backend.
     * v3 encodes atime and mtime together; use mtime for both when known. */
    put32(w,a->mtime?13u:5u);
    put32(w,(uint32_t)(a->size>>32));put32(w,(uint32_t)a->size);
    put32(w,a->is_dir?0040555u:0100444u);
    if(a->mtime){put32(w,a->mtime);put32(w,a->mtime);}
}
static void named(writer *w,uint32_t id,const char *name,const char *longname,const wb_sftp_attr *a){
    msg(w,NAME,id);put32(w,1);str(w,name);str(w,longname);attrs(w,a);
}
static void dir_name(writer *w,uint32_t id,const char *name,const wb_sftp_attr *a){
    /* OpenSSH displays NAME.longname verbatim for directory listings.
     * Mark unavailable nlink/uid/gid/time as unknown, never as root/epoch.
     * The filename and machine-readable wire attrs are unchanged. */
    char time[24]="mtime=?";
    if(a->mtime)snprintf(time,sizeof time,"mtime=%" PRIu32,a->mtime);
    char line[WB_SFTP_NAME_MAX+80];
    int n=snprintf(line,sizeof line,"%s ? ? ? %" PRIu64 " %s %s",
        a->is_dir?"dr-xr-xr-x":"-r--r--r--",a->size,time,name);
    if(n<0 || (size_t)n>=sizeof line){w->bad=1;return;}
    named(w,id,name,line,a);
}
static void status(writer *w,uint32_t id,int fx){
    const char *text;
    switch(fx){
    case WB_SFTP_OK:text="OK";break;
    case WB_SFTP_EOF:text="EOF";break;
    case WB_SFTP_NO_FILE:text="not found";break;
    case WB_SFTP_DENIED:text="not permitted";break;
    case WB_SFTP_BAD_MESSAGE:text="invalid request";break;
    case WB_SFTP_UNSUPPORTED:text="unsupported";break;
    default:fx=WB_SFTP_FAILURE;text="operation failed";break;
    }
    msg(w,STATUS,id);put32(w,(uint32_t)fx);str(w,text);str(w,"");
}
int wb_sftp_name_ok(const char *s,size_t n){
    if(!s||!n||n>WB_SFTP_NAME_MAX||s[n-1]=='.'||s[n-1]==' ')return 0;
    for(size_t i=0;i<n;i++){
        unsigned c=(unsigned char)s[i];
        if(c<32||c==127||c==':'||c=='/'||c=='\\')return 0;
    }return 1;
}
static int pathof(span a,char path[WB_SFTP_PATH_MAX]){
    size_t n=a.n,pos=0,out=1;path[0]='/';
    if(!a.s||!n||n>=WB_SFTP_PATH_MAX)return 0;
    if(n==1&&(a.s[0]=='/'||a.s[0]=='.')){path[1]=0;return 1;}
    if(a.s[0]=='/')pos++;
    while(pos<n){
        size_t start=pos;while(pos<n&&a.s[pos]!='/')pos++;
        size_t z=pos-start;
        if(!wb_sftp_name_ok((const char*)a.s+start,z))return 0;
        if(out!=1){if(out>=WB_SFTP_PATH_MAX-1)return 0;path[out++]='/';}
        if(z>=WB_SFTP_PATH_MAX-out)return 0;
        memcpy(path+out,a.s+start,z);out+=z;
        if(pos<n)pos++;  /* one trailing slash is canonicalized */
    }
    path[out]=0;return 1;
}
void wb_sftp_init(wb_sftp_ro *s,const wb_sftp_ops *ops){memset(s,0,sizeof *s);s->ops=ops;}
void wb_sftp_enable_write(wb_sftp_ro *s,const wb_sftp_write_ops *w){
    if(s && w && w->open && w->write && w->finish && w->mkdir)s->create=w;
}
void wb_sftp_reset(wb_sftp_ro *s){
    if(!s)return;
    for(unsigned i=0;i<WB_SFTP_HANDLES;i++){
        wb_sftp_handle *h=&s->handles[i];
        if(h->used&&h->writer)(void)s->create->finish(s->create->ctx,h->writer,0);
        else if(h->used&&s->ops&&s->ops->close)(void)s->ops->close(s->ops->ctx,h->fd,h->dir);
        h->used=0;
    }s->initialized=0;
}
static wb_sftp_handle *lookup(wb_sftp_ro *s,span token){
    if(token.n!=8)return NULL;
    uint32_t slot=num32(token.s),serial=num32(token.s+4);
    if(slot>=WB_SFTP_HANDLES)return NULL;
    wb_sftp_handle *h=&s->handles[slot];return h->used&&h->serial==serial?h:NULL;
}
static void open_file(wb_sftp_ro *s,writer *w,uint32_t id,const char *path,int dir,uint64_t hint_size){
    unsigned i=0;while(i<WB_SFTP_HANDLES&&s->handles[i].used)i++;
    if(i==WB_SFTP_HANDLES||s->last_serial==UINT32_MAX){status(w,id,WB_SFTP_FAILURE);return;}
    int fd=-1,fx;void *stream=NULL;uint64_t total=0;
    if(dir==2){
        for(unsigned j=0;j<WB_SFTP_HANDLES;j++)if(s->handles[j].used&&s->handles[j].writer){
            status(w,id,WB_SFTP_FAILURE);return;
        }
        fx=s->create->open(s->create->ctx,path,&stream);
        if(fx||!stream){status(w,id,fx?fx:WB_SFTP_FAILURE);return;}
        if(hint_size<=WB_TRANSFER_MAX)total=hint_size;
    }else{
        fx=s->ops->open(s->ops->ctx,path,dir,&fd);
        if(fx||fd<0){status(w,id,fx?fx:WB_SFTP_FAILURE);return;}
        if(!dir&&s->ops->fstat){
            wb_sftp_attr a={0};
            if(s->ops->fstat(s->ops->ctx,fd,0,&a)==WB_SFTP_OK&&!a.is_dir)total=a.size;
        }
    }
    wb_sftp_handle *h=&s->handles[i];*h=(wb_sftp_handle){
        .used=1,.dir=dir==1,.fd=fd,.serial=++s->last_serial,.writer=stream,.total=total};
    msg(w,HANDLE,id);put32(w,8);put32(w,i);put32(w,h->serial);
}
/* Validate v3 open attributes; capture optional SSH_FILEXFER_ATTR_SIZE hint
 * (used only for the local progress bar, never as a storage trust boundary). */
static int open_attrs(reader *r,uint64_t *size_out){
    uint32_t f=u32(r);if(f&~15u)return 0;
    if(f&1){
        uint64_t sz=((uint64_t)u32(r)<<32)|u32(r);
        if(size_out)*size_out=sz;
    }
    if(f&2){(void)u32(r);(void)u32(r);}
    if(f&4)(void)u32(r);
    if(f&8){(void)u32(r);(void)u32(r);}
    return done(r);
}
int wb_sftp_reply(wb_sftp_ro *s,const uint8_t *body,size_t n,uint8_t *out,size_t cap,size_t *outn){
    if(!outn)return -1;
    *outn=0;
    if(!s||!s->ops||!body||!out||n<5||n>WB_SFTP_PACKET_MAX||cap<64||
        !s->ops->open||!s->ops->close||!s->ops->read||!s->ops->readdir||!s->ops->stat)return -1;
    unsigned kind=body[0];reader r={body+1,n-1,0};writer w={out,0,cap,0};
    uint32_t id=u32(&r);int fx;
    if(kind==INIT){
        if(s->initialized||id<3)return -1;
        while(!done(&r)){(void)string(&r);(void)string(&r);if(r.bad)return -1;}
        s->initialized=1;byte(&w,VERSION);put32(&w,3);
    }else if(!s->initialized)return -1;
    else if(kind==REALPATH||kind==STAT||kind==LSTAT||kind==OPEN||kind==OPENDIR||(kind==MKDIR&&s->create)){
        char path[WB_SFTP_PATH_MAX];span operand=string(&r);uint32_t flags=0;uint64_t hint_size=0;
        if(kind==OPEN)flags=u32(&r);
        if(r.bad||((kind==OPEN||kind==MKDIR)?!open_attrs(&r,kind==OPEN?&hint_size:NULL):!done(&r)))status(&w,id,WB_SFTP_BAD_MESSAGE);
        else if(!pathof(operand,path))status(&w,id,WB_SFTP_DENIED);
        else if(kind==OPEN&&flags!=1u){
            /* OpenSSH scp uses WRITE|CREATE|TRUNC even for a fresh file.
             * TRUNC is never honored on existing files; native publish is no-replace. */
            if(!s->create||!strcmp(path,"/")||(flags!=10u&&flags!=26u&&flags!=42u))
                status(&w,id,WB_SFTP_DENIED);
            else open_file(s,&w,id,path,2,hint_size);
        }else if(kind==MKDIR)status(&w,id,strcmp(path,"/")?s->create->mkdir(s->create->ctx,path):WB_SFTP_DENIED);
        else if(kind==OPEN||kind==OPENDIR)open_file(s,&w,id,path,kind==OPENDIR,0);
        else {
            wb_sftp_attr a={0};fx=s->ops->stat(s->ops->ctx,path,&a);
            if(fx==WB_SFTP_NO_FILE&&kind==REALPATH&&s->create&&strcmp(path,"/")){
                /* OpenSSH resolves the future directory before recursive MKDIR.
                 * Canonical NAME only after its existing parent resolves to a real
                 * directory. Attribute flags 0 deliberately make no claim about
                 * the non-existent leaf. MKDIR/OPEN revalidate at mutation. */
                char parent[WB_SFTP_PATH_MAX];strcpy(parent,path);
                char *slash=strrchr(parent,'/');if(slash==parent)parent[1]=0;else *slash=0;
                wb_sftp_attr pa={0};fx=s->ops->stat(s->ops->ctx,parent,&pa);
                if(fx||!pa.is_dir)status(&w,id,fx?fx:WB_SFTP_DENIED);
                else{msg(&w,NAME,id);put32(&w,1);str(&w,path);str(&w,path);put32(&w,0);}
            }else if(fx)status(&w,id,fx);
            else if(kind==REALPATH)named(&w,id,path,path,&a);
            else {msg(&w,ATTRS,id);attrs(&w,&a);}
        }
    }else if(kind==FSETSTAT&&s->create){
        /* OpenSSH requests its final size even without -p. Accept only an
         * exact length verification on the currently staged file. Never extend,
         * truncate, change mode, or modify a committed object. */
        wb_sftp_handle *h=lookup(s,string(&r));uint32_t mask=u32(&r);
        if(!h||!h->writer||mask!=1u)status(&w,id,WB_SFTP_DENIED);
        else{
            uint64_t expected=(uint64_t)u32(&r)<<32;expected|=u32(&r);
            fx=!done(&r)?WB_SFTP_BAD_MESSAGE:(h->poison||h->offset!=expected?WB_SFTP_FAILURE:WB_SFTP_OK);
            if(fx)h->poison=1;
            status(&w,id,fx);
        }
    }else if(kind==WRITE&&s->create){
        wb_sftp_handle *h=lookup(s,string(&r));uint64_t off=(uint64_t)u32(&r)<<32;off|=u32(&r);
        span data=string(&r);fx=WB_SFTP_DENIED;
        if(h&&h->writer){
            if(!done(&r))fx=WB_SFTP_BAD_MESSAGE;
            else if(h->poison||off!=h->offset||data.n>WB_SFTP_DATA_MAX||
                    h->offset>WB_TRANSFER_MAX||data.n>WB_TRANSFER_MAX-h->offset)fx=WB_SFTP_FAILURE;
            else {fx=s->create->write(s->create->ctx,h->writer,data.s,data.n);if(!fx)h->offset+=data.n;}
            if(fx)h->poison=1;
        }
        status(&w,id,fx);
    }else if(kind==CLOSE||kind==READ||kind==READDIR||kind==FSTAT){
        wb_sftp_handle *h=lookup(s,string(&r));uint64_t off=0;uint32_t len=0;
        if(kind==READ){off=(uint64_t)u32(&r)<<32;off|=u32(&r);len=u32(&r);}
        if(!done(&r))status(&w,id,WB_SFTP_BAD_MESSAGE);
        else if(!h||(kind==READ&&(h->dir||h->writer))||(kind==READDIR&&!h->dir))status(&w,id,WB_SFTP_FAILURE);
        else if(kind==CLOSE){
            fx=h->writer?s->create->finish(s->create->ctx,h->writer,!h->poison)
                        :s->ops->close(s->ops->ctx,h->fd,h->dir);
            h->used=0;status(&w,id,h->poison?WB_SFTP_FAILURE:fx);
        }
        else if(kind==FSTAT){
            wb_sftp_attr a={0};
            if(h->writer){a.size=h->offset;fx=WB_SFTP_OK;}
            else fx=s->ops->fstat?s->ops->fstat(s->ops->ctx,h->fd,h->dir,&a):WB_SFTP_UNSUPPORTED;
            if(fx)status(&w,id,fx);else {msg(&w,ATTRS,id);attrs(&w,&a);}
        }else if(kind==READ){
            size_t want=len,got=0;if(want>WB_SFTP_DATA_MAX)want=WB_SFTP_DATA_MAX;
            if(want>w.cap-9)want=w.cap-9;
            fx=want?s->ops->read(s->ops->ctx,h->fd,off,out+9,want,&got):WB_SFTP_OK;
            if(fx||got>want)status(&w,id,fx?fx:WB_SFTP_FAILURE);
            else if(want&&!got)status(&w,id,WB_SFTP_EOF);
            else {
                if(off+got>h->offset)h->offset=off+got;
                msg(&w,DATA,id);put32(&w,(uint32_t)got);w.n+=got;
            }
        }else{
            char name[WB_SFTP_NAME_MAX+1]={0};wb_sftp_attr a={0};
            fx=s->ops->readdir(s->ops->ctx,h->fd,name,sizeof name,&a);
            char *end=memchr(name,0,sizeof name);
            if(fx)status(&w,id,fx);
            else if(!end||!wb_sftp_name_ok(name,(size_t)(end-name)))status(&w,id,WB_SFTP_FAILURE);
            else dir_name(&w,id,name,&a);
        }
    }else{
        int mutating=kind==WRITE||kind==SETSTAT||kind==FSETSTAT||kind==REMOVE||
                     kind==MKDIR||kind==RMDIR||kind==RENAME||kind==SYMLINK;
        status(&w,id,mutating?WB_SFTP_DENIED:WB_SFTP_UNSUPPORTED);
    }
    if(w.bad)return -1;
    *outn=w.n;return 0;
}
