#include "wb_shell_channel.h"
#include "wb_ver.h"
#include <string.h>
#ifdef WB_TTY_FILE
#include <stdlib.h>
#endif
#ifdef WB_GAME_FEATURE
#include "wb_game_vita.h"
#include "wb_game_io.h"
#endif
#ifdef WB_SCREEN_MIRROR
#include "wb_screen_mirror.h"
#endif

static int append(wb_shell_channel *s,const char *p,size_t n) {
    if (n>sizeof s->pending-s->queued) {s->overflow=true;return -1;}
    if (n) memcpy(s->pending+s->queued,p,n);
    s->queued+=n;return 0;
}
/* Only this editor writes terminal controls. Command output cannot inject
 * escape sequences or move the cursor; normalize mixed line endings. */
static int plain(void *ctx,const char *p,size_t n) {
    wb_shell_channel *s=ctx;
    for (size_t i=0;i<n;i++) {
        unsigned c=(unsigned char)p[i];
        if(c=='\r') continue;
        if(c=='\n') {if(append(s,"\r\n",2))return -1;}
        else {char b=(c>=32 && c<127)?(char)c:(c=='\t'?' ':'?');if(append(s,&b,1))return -1;}
    }
    return 0;
}
static int prompt(wb_shell_channel *s) {
    wb_out out={s,plain};return wb_shell_prompt(&s->shell,&out);
}
#ifdef WB_TTY_FILE
void wb_sh_abort_file(wb_shell_channel *s){
    if(s&&s->file){wb_tty_abort(s->file);free(s->file);s->file=NULL;}
}
static int file_start(wb_shell_channel *s){
    if(!s->echo)return plain(s,"TTY1 ERR pty-required\n",22);
    s->file=calloc(1,sizeof *s->file);
    const char *error=s->file?wb_tty_begin(s->file,s->line):"nomem";
    if(error){
        wb_sh_abort_file(s);
        return append(s,"TTY1 ERR ",9)||append(s,error,strlen(error))||append(s,"\r\n",2)?-1:0;
    }
    return append(s,s->file->reply,strlen(s->file->reply));
}
static int file_input(wb_shell_channel *s,unsigned c){
    wb_tty_file *f=s->file;int k=1;
    if(c==3){memcpy(f->line,"CANCEL",6);f->n=6;c='\n';}
    if(c=='\n'||c=='\r'){
        s->ignore_lf=c=='\r';k=wb_tty_frame(f,&s->private_pending);
        if(append(s,f->reply,strlen(f->reply))<0)return -1;
    }else if(c<32||c>=127||f->n>=sizeof f->line-1){
        /* Do not reinterpret any remainder as shell commands. */
        static const char e[]="TTY1 ERR invalid-frame\r\n";
        if(append(s,e,sizeof e-1)<0)return -1;
        k=-1;
    }else{f->line[f->n++]=(char)c;return 0;}
    if(k<=0){
        wb_sh_abort_file(s);s->ri=s->rn;
        if(k<0){s->file_fault=true;s->closing=true;}
        else if(prompt(s)<0)return -1;
    }
    return 1;
}
#endif
int wb_sh_start(wb_shell_channel *s,bool tty) {
    memset(s,0,sizeof *s);s->echo=tty;wb_shell_init(&s->shell);
    static const char banner[]="VITA AGENT TERMINAL " WB_VERSION " (Workbench)\r\nType help for commands.\r\n";
    return append(s,banner,sizeof banner-1) || prompt(s) ? -1 : 0;
}
static int enter(wb_shell_channel *s,const wb_shell_ops *ops,unsigned *commands) {
    if(s->echo && append(s,"\r\n",2))return -1;
    size_t start=s->queued;int rc=0;s->line[s->used]=0;
#ifdef WB_TTY_FILE
    char tree_reply[96];
#endif
    if(s->bad_line) rc=append(s,"ERR invalid or long line\r\n",26);
#ifdef WB_TTY_FILE
    else if(wb_tty_tree_command(s->line,s->echo,tree_reply,sizeof tree_reply)){
        ++*commands;rc=append(s,tree_reply,strlen(tree_reply));
    }
    else if(wb_tty_recognizes(s->line)){++*commands;rc=file_start(s);}
#endif
#ifdef WB_GAME_FEATURE
    else if(!strcmp(s->line,WBG_COMMAND)) {
        ++*commands;
        const char *err=wb_gv_start(s->shell.cwd,s->echo,s->line,s->incoming+s->ri,s->rn-s->ri,s->ignore_lf,&s->game_owner);
        s->ri=s->rn;s->used=0;s->escape=0;s->bad_line=false;s->ignore_lf=false;
        if(err){if(plain(s,err,strlen(err))<0)return -1;return prompt(s);}
        static const char msg[]="PYTHON runtime=MicroPython-1.25.0 sha256=" WBG_SCRIPT_SHA "\r\n";
        return append(s,msg,sizeof msg-1);
    }
#endif
    else if(s->used) {
        wb_out out={s,plain};(*commands)++;
        rc=wb_shell_run(&s->shell,s->line,&out,ops);
        if(s->overflow) {
            /* Avoid a truncated success receipt or continuation of an overrun. */
            s->queued=start;s->overflow=false;
            rc=append(s,"ERR output-limit\r\n",18);
        }
    }
    s->used=0;s->escape=0;s->bad_line=false;
    if(rc<0)return -1;
#ifdef WB_TTY_FILE
    if(s->file)return 0;
#endif
    if(rc==1) {s->closing=true;return 0;}
    if(s->queued>start && s->pending[s->queued-1]!='\n' && append(s,"\r\n",2))return -1;
    return prompt(s);
}
/* No read callback or command dispatcher exists on this path. */
static int flush_queue(wb_shell_channel *s,void *io,
                       int (*wr)(void *,const uint8_t *,size_t)) {
    if(s->queued) {
        size_t n=s->queued-s->sent;if(n>4096)n=4096;
        int k=wr(io,(const uint8_t*)s->pending+s->sent,n);
        if(k<0 || (size_t)k>n)return -1;
        s->sent+=(size_t)k;
        if(s->sent==s->queued){
            s->queued=s->sent=0;
#ifdef WB_TTY_FILE
            s->private_pending=false;
#endif
        }
        return 1;
    }
    return 0;
}
static int pump(wb_shell_channel *s,void *io,
               int (*rd)(void *,uint8_t *,size_t),
               int (*wr)(void *,const uint8_t *,size_t),
               const wb_shell_ops *ops,unsigned *commands) {
    if(s->queued)return flush_queue(s,io,wr);
    if(s->closing){
#ifdef WB_TTY_FILE
        if(s->file_fault)return -1; /* flushed TTY1 ERR + failing channel status */
#endif
        return 0;
    }
#ifdef WB_GAME_FEATURE
    if(s->game_owner)return wb_gv_tick(s->game_owner,io,rd,wr);
#endif
    if(s->ri==s->rn) {
        size_t room=sizeof s->incoming;
#ifdef WB_TTY_FILE
        if(!s->file)room=256; /* editor & game keep their original read bounds */
#endif
        int k=rd(io,s->incoming,room);
        if(k==-2)return 0; /* never execute an unterminated line on EOF */
        if(k<0 || (size_t)k>room)return -1;
        s->ri=0;s->rn=(size_t)k;
    }
    while(s->ri<s->rn) {
        unsigned c=s->incoming[s->ri++];
        if(s->ignore_lf) {s->ignore_lf=false;if(c=='\n')continue;}
#ifdef WB_TTY_FILE
        if(s->file){int k=file_input(s,c);if(k)return k;continue;}
#endif
        if(c=='\r' || c=='\n') {
            s->ignore_lf=(c=='\r');if(s->escape)s->bad_line=true;
            return enter(s,ops,commands)<0?-1:1; /* one command per service tick */
        }
        if(c==3 || c==21) { /* Ctrl-C / Ctrl-U: cancel the whole line */
            s->used=0;s->bad_line=false;s->escape=0;
            if(append(s,c==3?"^C\r\n":"^U\r\n",4) || prompt(s))return -1;
            continue;
        }
        if(c==27) {s->escape=1;continue;}
        if(s->escape) {
            if(s->escape==1 && (c=='['||c=='O')){s->escape=2;continue;}
            if(s->escape==2 && c>=0x20 && c<=0x3f)continue;
            if(s->escape!=2 || c<0x40 || c>0x7e)s->bad_line=true;
            s->escape=0;continue; /* navigation keys do not enter the command */
        }
        if(c==4 && !s->used && !s->bad_line) {s->closing=true;return 1;}
        if(c==8 || c==127) {
            if(s->used && !s->bad_line){s->used--;if(s->echo && append(s,"\b \b",3))return -1;}
            continue;
        }
        if(c=='\t' && s->echo){
            char edited[WB_SH_LINE];s->line[s->used]=0;
            if(!s->bad_line&&wb_shell_complete(&s->shell,s->line,ops,edited)){
                size_t shared=0,n=strlen(edited);
                while(shared<s->used && shared<n && s->line[shared]==edited[shared])++shared;
                size_t erased=s->used-shared,added=n-shared;
                if(3*erased+added<=sizeof s->pending-s->queued){
                    for(size_t j=0;j<erased;j++)if(append(s,"\b \b",3))return -1;
                    if(append(s,edited+shared,added))return -1;
                    memcpy(s->line,edited,n+1);s->used=n;
                }
            }
            return 1; /* at most one bounded lookup per poll; never Enter */
        }
        if(c<32 || c>=127 || s->used==sizeof s->line-1){s->bad_line=true;continue;}
        if(s->bad_line)continue;
        char ch=(char)c;s->line[s->used++]=ch;
        if(s->echo && append(s,&ch,1))return -1;
    }
    return 1;
}

/* Only authenticated/admitted SSH shell_service calls this pump. SSH exec,
 * subsystem (including SFTP), authentication, and binary upload I/O do not.
 * The terminal stream is the output *after* editing/echo and serialization.
 * Neither uncommitted bytes nor raw inbound keystrokes are separately teed. */
void wb_sh_set_geometry(wb_shell_channel *s,int cols,int rows) {
#ifdef WB_SCREEN_MIRROR
    if(!s)return;
    s->cols=cols>0?(unsigned)cols:0;s->rows=rows>0?(unsigned)rows:0;
    if(s->mirror_started)wb_mirror_geometry(s->cols,s->rows);
#else
    (void)s;(void)cols;(void)rows;
#endif
}
#ifdef WB_SCREEN_MIRROR
typedef struct { wb_shell_channel *s;void *ctx;
    int (*rd)(void*,uint8_t*,size_t);int (*wr)(void*,const uint8_t*,size_t);
} shio;
static int shrd(void *v,uint8_t *p,size_t n){shio *f=v;return f->rd(f->ctx,p,n);}
static int shwr(void *v,const uint8_t *p,size_t n){
    shio *f=v;int k=f->wr(f->ctx,p,n);
#ifdef WB_TTY_FILE
    if(f->s->private_pending)return k; /* data/ACK frames are transport, not shared screen text */
#endif
    if(k>0 && (size_t)k<=n) {
        if(!f->s->mirror_started){
            wb_mirror_begin();wb_mirror_geometry(f->s->cols,f->s->rows);
            f->s->mirror_started=true;
        }
        wb_mirror_write(p,(size_t)k);
    }
    return k;
}
#endif
int wb_sh_flush(wb_shell_channel *s,void *io,int (*wr)(void*,const uint8_t*,size_t)) {
#ifdef WB_SCREEN_MIRROR
    shio f={s,io,NULL,wr};return flush_queue(s,&f,shwr);
#else
    return flush_queue(s,io,wr);
#endif
}
int wb_sh_pump(wb_shell_channel *s,void *io,
               int (*rd)(void*,uint8_t*,size_t),int (*wr)(void*,const uint8_t*,size_t),
               const wb_shell_ops *ops,unsigned *commands) {
#ifdef WB_SCREEN_MIRROR
    shio f={s,io,rd,wr};
    return pump(s,&f,shrd,shwr,ops,commands);
#else
    return pump(s,io,rd,wr,ops,commands);
#endif
}
