#include "wb_shell_channel.h"
#include "wb_ver.h"
#include <stdio.h>
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
static int plain(void *ctx,const char *p,size_t n) {
    wb_shell_channel *s=ctx;
    for (size_t i=0;i<n;i++) {
        unsigned c=(unsigned char)p[i];
        if(c=='\r') continue;
        if(c=='\n') {if(append(s,"\r\n",2))return -1;}
#ifdef WB_SHELL2
        else if(c==27 && s->echo && i+2<n && p[i+1]=='[') {
            /* Permit only bounded ANSI SGR color codes (\033[0-9;...m). */
            size_t j=i+2;
            while(j<n && j-i<16 && ((p[j]>='0'&&p[j]<='9')||p[j]==';'))j++;
            if(j<n && p[j]=='m') {
                if(append(s,p+i,j-i+1))return -1;
                i=j;continue;
            }
            char q='?';if(append(s,&q,1))return -1;
        }
#endif
        else {char b=(c>=32 && c<127)?(char)c:(c=='\t'?' ':'?');if(append(s,&b,1))return -1;}
    }
    return 0;
}
static int prompt(wb_shell_channel *s) {
    wb_out out={s,plain};return wb_shell_prompt(&s->shell,&out);
}
static int redraw_line(wb_shell_channel *s, size_t old_used, size_t old_cursor) {
    if (!s->echo) return 0;
    /* Move back to start of input, rewrite entire line, pad if shrunk, then move to cursor */
    for (size_t i = 0; i < old_cursor; i++) if (append(s, "\b", 1)) return -1;
    if (s->used && append(s, s->line, s->used)) return -1;
    size_t pad = old_used > s->used ? old_used - s->used : 0;
    for (size_t i = 0; i < pad; i++) if (append(s, " ", 1)) return -1;
    size_t back = pad + (s->used - s->cursor);
    for (size_t i = 0; i < back; i++) if (append(s, "\b", 1)) return -1;
    return 0;
}
static void hist_push(wb_shell_channel *s, const char *line) {
    if (!line || !*line) return;
    if (s->hist_count > 0 && !strcmp(s->hist[(s->hist_count - 1) % WB_SH_HIST], line)) return;
    size_t len = strlen(line);
    if (len >= WB_SH_LINE) len = WB_SH_LINE - 1;
    memcpy(s->hist[s->hist_count % WB_SH_HIST], line, len);
    s->hist[s->hist_count % WB_SH_HIST][len] = 0;
    s->hist_count++;
    s->shell.hist_count = s->hist_count;
}
static int hist_apply(wb_shell_channel *s, int dir) {
    if (!s->hist_count) return 0;
    const unsigned avail = s->hist_count < WB_SH_HIST ? s->hist_count : WB_SH_HIST;
    unsigned next = s->hist_nav;
    if (dir < 0) {
        if (next < avail) next++;
        else return 0;
    } else {
        if (next > 0) next--;
        else return 0;
    }
    s->hist_nav = next;
    const size_t old_used = s->used, old_cursor = s->cursor;
    if (next == 0) {
        s->used = 0; s->cursor = 0; s->line[0] = 0;
    } else {
        const char *h = s->hist[(s->hist_count - next) % WB_SH_HIST];
        size_t n = strlen(h);
        if (n >= sizeof s->line) n = sizeof s->line - 1;
        memcpy(s->line, h, n); s->line[n] = 0;
        s->used = n; s->cursor = n;
    }
    return redraw_line(s, old_used, old_cursor);
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
    s->shell.hist=s->hist;s->shell.hist_cap=WB_SH_HIST;s->shell.hist_count=0;
#ifdef WB_SHELL2
    s->shell.color=tty;
#endif
    /* Exact banner is parsed by the PC terminal client (wbterm.py). */
    static const char banner[]="VITA AGENT TERMINAL " WB_VERSION " (Workbench)\r\nType help for commands.\r\n";
    return append(s,banner,sizeof banner-1) || prompt(s) ? -1 : 0;
}
static int flush_queue(wb_shell_channel *s,void *io,int (*wr)(void *,const uint8_t *,size_t));
typedef struct {wb_shell_channel *s;void *io;int (*wr)(void *,const uint8_t *,size_t);} app_output;
static int app_drain(app_output *o){
    while(o->s->queued){
        const size_t before=o->s->sent;
        if(flush_queue(o->s,o->io,o->wr)<0)return -1;
        if(o->s->queued && o->s->sent==before)return -1;
    }
    return 0;
}
static int app_plain(void *ctx,const char *p,size_t n){
    app_output *o=ctx;
    return plain(o->s,p,n)<0 ? -1 : app_drain(o);
}
static bool is_single_word(const char *s, const char *word){
    const size_t wl = strlen(word);
    while(*s==' '||*s=='\t')s++;
    if(strncmp(s,word,wl))return false;
    s+=wl;while(*s==' '||*s=='\t')s++;
    return *s==0;
}
static int enter(wb_shell_channel *s,const wb_shell_ops *ops,unsigned *commands,
                 void *io,int (*wr)(void *,const uint8_t *,size_t)) {
    if(s->echo && append(s,"\r\n",2))return -1;
    size_t start=s->queued;int rc=0;s->line[s->used]=0;
    s->hist_nav=0;
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
        s->ri=s->rn;s->used=0;s->cursor=0;s->escape=0;s->esc_len=0;s->bad_line=false;s->ignore_lf=false;
        if(err){if(plain(s,err,strlen(err))<0)return -1;return prompt(s);}
        static const char msg[]="PYTHON runtime=MicroPython-1.25.0 sha256=" WBG_SCRIPT_SHA "\r\n";
        return append(s,msg,sizeof msg-1);
    }
#endif
    else if(is_single_word(s->line,"clear")) {
        ++*commands;
        if(!s->echo)rc=plain(s,"ERR clear requires interactive PTY\n",35);
        else{
            rc=append(s,"\033[2J\033[H",7);
#ifdef WB_SCREEN_MIRROR
            if(rc==0)s->clear_after=s->queued;
#endif
        }
    }
#ifndef WB_SHELL2
    else if(is_single_word(s->line,"history")) {
        ++*commands;
        const unsigned avail = s->hist_count < WB_SH_HIST ? s->hist_count : WB_SH_HIST;
        const unsigned first = s->hist_count - avail;
        for (unsigned i = 0; i < avail; i++) {
            char row[WB_SH_LINE + 24];
            int n = snprintf(row, sizeof row, "%4u  %s\n", first + i + 1, s->hist[(first + i) % WB_SH_HIST]);
            if (n > 0 && plain(s, row, (size_t)n) < 0) { rc = -1; break; }
        }
    }
#endif
    else if(s->used) {
        if(!is_single_word(s->line,"history"))hist_push(s, s->line);
        app_output stream={s,io,wr};
        const bool streaming=wb_shell_streamed_app(s->line);
        if(streaming){if(app_drain(&stream)<0)return -1;start=0;}
        wb_out out=streaming?(wb_out){&stream,app_plain}:(wb_out){s,plain};(*commands)++;
        rc=wb_shell_run(&s->shell,s->line,&out,ops);
        if(s->overflow) {
            s->queued=start;s->overflow=false;
            rc=append(s,"ERR output-limit\r\n",18);
        }
    }
    s->used=0;s->cursor=0;s->escape=0;s->esc_len=0;s->bad_line=false;
    if(rc<0)return -1;
#ifdef WB_TTY_FILE
    if(s->file)return 0;
#endif
    if(rc==1) {s->closing=true;return 0;}
    if(s->queued>start && s->pending[s->queued-1]!='\n' && append(s,"\r\n",2))return -1;
    return prompt(s);
}
static int flush_queue(wb_shell_channel *s,void *io,
                       int (*wr)(void *,const uint8_t *,size_t)) {
    if(s->queued) {
        size_t n=s->queued-s->sent;if(n>4096)n=4096;
        int k=wr(io,(const uint8_t*)s->pending+s->sent,n);
        if(k<0 || (size_t)k>n)return -1;
        s->sent+=(size_t)k;
        if(s->sent==s->queued){
            s->queued=s->sent=0;
#ifdef WB_SCREEN_MIRROR
            s->clear_after=0;
#endif
#ifdef WB_TTY_FILE
            s->private_pending=false;
#endif
        }
        return 1;
    }
    return 0;
}
static int handle_csi(wb_shell_channel *s, unsigned final) {
    if (s->bad_line) return 0;
    if (final == 'A' && s->esc_len == 0) return hist_apply(s, -1); /* Up */
    if (final == 'B' && s->esc_len == 0) return hist_apply(s, 1);  /* Down */
    if (final == 'D' && s->esc_len == 0) { /* Left */
        if (s->cursor > 0) { s->cursor--; if (s->echo && append(s, "\b", 1)) return -1; }
        return 0;
    }
    if (final == 'C' && s->esc_len == 0) { /* Right */
        if (s->cursor < s->used) {
            char ch = s->line[s->cursor++];
            if (s->echo && append(s, &ch, 1)) return -1;
        }
        return 0;
    }
    if (final == 'H' || (final == '~' && s->esc_len == 1 && (s->esc_buf[0] == '1' || s->esc_buf[0] == '7'))) {
        while (s->cursor > 0) { s->cursor--; if (s->echo && append(s, "\b", 1)) return -1; }
        return 0;
    }
    if (final == 'F' || (final == '~' && s->esc_len == 1 && (s->esc_buf[0] == '4' || s->esc_buf[0] == '8'))) {
        if (s->cursor < s->used) {
            size_t tail = s->used - s->cursor;
            if (s->echo && append(s, s->line + s->cursor, tail)) return -1;
            s->cursor = s->used;
        }
        return 0;
    }
    if (final == '~' && s->esc_len == 1 && s->esc_buf[0] == '3') { /* Delete */
        if (s->cursor < s->used) {
            const size_t old_used = s->used, old_cursor = s->cursor;
            memmove(s->line + s->cursor, s->line + s->cursor + 1, s->used - s->cursor - 1);
            s->used--;
            return redraw_line(s, old_used, old_cursor);
        }
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
        if(s->file_fault)return -1;
#endif
        return 0;
    }
#ifdef WB_GAME_FEATURE
    if(s->game_owner)return wb_gv_tick(s->game_owner,io,rd,wr);
#endif
    if(s->ri==s->rn) {
        size_t room=sizeof s->incoming;
#ifdef WB_TTY_FILE
        if(!s->file)room=256;
#endif
        int k=rd(io,s->incoming,room);
        if(k==-2)return 0;
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
            return enter(s,ops,commands,io,wr)<0?-1:1;
        }
        if(c==3 || c==21) { /* Ctrl-C / Ctrl-U */
            s->used=0;s->cursor=0;s->hist_nav=0;s->bad_line=false;s->escape=0;s->esc_len=0;
            if(append(s,c==3?"^C\r\n":"^U\r\n",4) || prompt(s))return -1;
            continue;
        }
        if(c==1 && !s->bad_line) { /* Ctrl-A: Home */
            while(s->cursor>0){s->cursor--;if(s->echo&&append(s,"\b",1))return -1;}
            continue;
        }
        if(c==5 && !s->bad_line) { /* Ctrl-E: End */
            if(s->cursor<s->used){
                if(s->echo&&append(s,s->line+s->cursor,s->used-s->cursor))return -1;
                s->cursor=s->used;
            }
            continue;
        }
        if(c==11 && !s->bad_line) { /* Ctrl-K: kill to end */
            if(s->cursor<s->used){
                const size_t old_used=s->used,old_cursor=s->cursor;
                s->used=s->cursor;
                if(redraw_line(s,old_used,old_cursor)<0)return -1;
            }
            continue;
        }
        if(c==23 && !s->bad_line) { /* Ctrl-W: delete word before cursor */
            if(s->cursor>0){
                const size_t old_used=s->used,old_cursor=s->cursor;
                size_t pos=s->cursor;
                while(pos>0 && s->line[pos-1]==' ')pos--;
                while(pos>0 && s->line[pos-1]!=' ')pos--;
                memmove(s->line+pos,s->line+s->cursor,s->used-s->cursor);
                s->used-=(s->cursor-pos);s->cursor=pos;
                if(redraw_line(s,old_used,old_cursor)<0)return -1;
            }
            continue;
        }
        if(c==12 && s->echo && !s->bad_line) { /* Ctrl-L: clear screen */
            if(append(s,"\033[2J\033[H",7))return -1;
#ifdef WB_SCREEN_MIRROR
            s->clear_after=s->queued;
#endif
            if(prompt(s))return -1;
            if(s->used && append(s,s->line,s->used))return -1;
            for(size_t i=s->cursor;i<s->used;i++)if(append(s,"\b",1))return -1;
            continue;
        }
        if(c==27) {s->escape=1;s->esc_len=0;continue;}
        if(s->escape) {
            if(s->escape==1 && (c=='['||c=='O')){s->escape=2;s->esc_len=0;continue;}
            if(s->escape==2 && c>=0x20 && c<=0x3f){
                if(s->esc_len<sizeof s->esc_buf)s->esc_buf[s->esc_len++]=(char)c;
                continue;
            }
            if(s->escape==2 && c>=0x40 && c<=0x7e){
                s->escape=0;
                if(handle_csi(s,c)<0)return -1;
                s->esc_len=0;continue;
            }
            s->bad_line=true;s->escape=0;s->esc_len=0;continue;
        }
        if(c==4 && !s->used && !s->bad_line) {s->closing=true;return 1;}
        if(c==8 || c==127) {
            if(s->cursor && !s->bad_line){
                if(s->cursor==s->used){ /* classic erase at end of line */
                    s->used--;s->cursor--;
                    if(s->echo && append(s,"\b \b",3))return -1;
                }else{
                    const size_t old_used=s->used,old_cursor=s->cursor;
                    memmove(s->line+s->cursor-1,s->line+s->cursor,s->used-s->cursor);
                    s->cursor--;s->used--;
                    if(redraw_line(s,old_used,old_cursor)<0)return -1;
                }
            }
            continue;
        }
        if(c=='\t' && s->echo){
            char edited[WB_SH_LINE];s->line[s->used]=0;
            if(!s->bad_line && s->cursor==s->used){
                if(wb_shell_complete(&s->shell,s->line,ops,edited)){
                    size_t shared=0,n=strlen(edited);
                    while(shared<s->used && shared<n && s->line[shared]==edited[shared])++shared;
                    size_t erased=s->used-shared,added=n-shared;
                    if(3*erased+added<=sizeof s->pending-s->queued){
                        for(size_t j=0;j<erased;j++)if(append(s,"\b \b",3))return -1;
                        if(append(s,edited+shared,added))return -1;
                        memcpy(s->line,edited,n+1);s->used=n;s->cursor=n;
                    }
                }
#ifdef WB_SHELL2
                else if(s->used){
                    size_t mark=s->queued;
                    if(append(s,"\r\n",2)==0){
                        wb_out out={s,plain};
                        if(wb_shell_list_matches(&s->shell,s->line,ops,&out) && !s->overflow){
                            if(prompt(s)<0 || (s->used && append(s,s->line,s->used)<0))return -1;
                        }else{s->queued=mark;s->overflow=false;}
                    }
                }
#endif
            }
            return 1; /* at most one bounded lookup per poll; never Enter */
        }
        if(c<32 || c>=127 || s->used==sizeof s->line-1){s->bad_line=true;continue;}
        if(s->bad_line)continue;
        char ch=(char)c;
        if(s->cursor==s->used){
            s->line[s->used++]=ch;s->cursor++;
            if(s->echo && append(s,&ch,1))return -1;
        }else{
            const size_t old_used=s->used,old_cursor=s->cursor;
            memmove(s->line+s->cursor+1,s->line+s->cursor,s->used-s->cursor);
            s->line[s->cursor++]=ch;s->used++;
            if(redraw_line(s,old_used,old_cursor)<0)return -1;
        }
    }
    return 1;
}

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
    shio *f=v;const size_t base=f->s->sent;int k=f->wr(f->ctx,p,n);
#ifdef WB_TTY_FILE
    if(f->s->private_pending)return k;
#endif
    if(k>0 && (size_t)k<=n) {
        if(!f->s->mirror_started){
            wb_mirror_begin();wb_mirror_geometry(f->s->cols,f->s->rows);
            f->s->mirror_started=true;
        }
        if(f->s->clear_after && base+(size_t)k>=f->s->clear_after){
            const size_t tail=f->s->clear_after>base?f->s->clear_after-base:0;
            wb_mirror_begin();wb_mirror_geometry(f->s->cols,f->s->rows);
            f->s->mirror_started=true;f->s->clear_after=0;
            if((size_t)k>tail)wb_mirror_write(p+tail,(size_t)k-tail);
        }else wb_mirror_write(p,(size_t)k);
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
