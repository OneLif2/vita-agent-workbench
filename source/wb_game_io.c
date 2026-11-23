#include "wb_game_io.h"
#include <string.h>
_Static_assert(ATOMIC_INT_LOCK_FREE==2, "game queue indices must be lock free");
_Static_assert((WBG_TX&(WBG_TX-1))==0 && (WBG_INPUT_LINES&(WBG_INPUT_LINES-1))==0
               && (WBG_ECHO&(WBG_ECHO-1))==0,"queues require power of two");
static int abort_game(wb_game_io *s,unsigned why){
    unsigned zero=WBG_NORMAL;
    atomic_compare_exchange_strong(&s->cause,&zero,why);
    atomic_store(&s->state,WBG_CANCELLED);
    return -1;
}
void wbg_init(wb_game_io *s){
    memset(s,0,sizeof(*s));
    atomic_init(&s->state,WBG_IDLE);atomic_init(&s->cause,WBG_NORMAL);
    atomic_init(&s->rx_w,0);atomic_init(&s->rx_r,0);
    atomic_init(&s->tx_w,0);atomic_init(&s->tx_r,0);
    atomic_init(&s->waiting,0);atomic_init(&s->echo_owed,0);
}
int wbg_start(wb_game_io *s,uint64_t owner,const char *cmd,const char *sha,int admitted,int tty){
    if(!s || atomic_load(&s->state)!=WBG_IDLE || !owner || !admitted || !cmd || !sha ||
       strcmp(cmd,WBG_COMMAND) || strcmp(sha,WBG_SCRIPT_SHA))return 0;
    s->owner=owner;s->tty=!!tty;atomic_store(&s->state,WBG_ACTIVE);return 1;
}
int wbg_write(wb_game_io *s,const uint8_t *p,size_t n){
    if(atomic_load(&s->state)!=WBG_ACTIVE)return -1;
    if(n>WBG_WRITE_MAX || (n&&!p))return abort_game(s,WBG_BAD_OUTPUT);
    size_t need=n;
    for(size_t i=0;i<n;i++){
        unsigned c=p[i];
        if(c=='\n')++need;
        else if(c=='\t' || (c>=32&&c<127))continue;
        else if(c==0xe2 && i+2<n && p[i+1]==0x99 && p[i+2]==0xa5)i+=2;
        else return abort_game(s,WBG_BAD_OUTPUT);
    }
    unsigned w=atomic_load(&s->tx_w),r=atomic_load(&s->tx_r);
    if(need>WBG_TX-(w-r))return 0;
    for(size_t i=0;i<n;i++){
        if(p[i]=='\n')s->tx[w++&(WBG_TX-1)]='\r';
        s->tx[w++&(WBG_TX-1)]=p[i]=='\t'?' ':p[i];
    }
    atomic_store(&s->tx_w,w);return 1;
}
int wbg_flushed(wb_game_io *s){
    if(atomic_load(&s->state)!=WBG_ACTIVE)return -1;
    return atomic_load(&s->tx_w)==atomic_load(&s->tx_r);
}
int wbg_readline(wb_game_io *s,char dst[WBG_LINE+1]){
    int flushed=wbg_flushed(s);if(flushed<0)return -1;
    atomic_store(&s->waiting,1);
    if(!flushed)return 0; /* never give early typeahead to input() over a pending prompt */
    unsigned r=atomic_load(&s->rx_r);
    if(r==atomic_load(&s->rx_w) || atomic_load(&s->echo_owed))return 0;
    memcpy(dst,s->lines[r&(WBG_INPUT_LINES-1)],WBG_LINE+1);
    atomic_store(&s->rx_r,r+1);atomic_store(&s->waiting,0);return 1;
}
void wbg_finish(wb_game_io *s,int ok){
    if(!ok){abort_game(s,WBG_RUNNER_FAILED);return;}
    unsigned active=WBG_ACTIVE;atomic_compare_exchange_strong(&s->state,&active,WBG_DONE);
}
void wbg_disconnect(wb_game_io *s,uint64_t owner){
    if(s && owner && s->owner==owner)abort_game(s,WBG_DISCONNECT);
}
static int echo_text(wb_game_io *s,const char *str,size_t n){
    if(!s->tty || !atomic_load(&s->waiting))return 1; /* piped/pre-prompts: no echo */
    if(n>WBG_ECHO-(s->echo_w-s->echo_r))return abort_game(s,WBG_INPUT_LIMIT);
    for(size_t i=0;i<n;i++)s->echo[s->echo_w++&(WBG_ECHO-1)]=(uint8_t)str[i];
    atomic_store(&s->echo_owed,1);return 1;
}
static int feed(wb_game_io *s,const uint8_t *p,size_t n){
    if(n>256 || (n&&!p))return abort_game(s,WBG_INPUT_LIMIT);
    for(size_t i=0;i<n;i++){
        uint8_t c=p[i];
        if(s->skip_lf){s->skip_lf=0;if(c=='\n')continue;}
        if(c==3 || c==4)return abort_game(s,c==3?WBG_INTERRUPT:WBG_EOF);
        if(c=='\r' || c=='\n'){
            unsigned w=atomic_load(&s->rx_w),r=atomic_load(&s->rx_r);
            if(w-r>=WBG_INPUT_LINES)return abort_game(s,WBG_INPUT_LIMIT);
            if(echo_text(s,"\r\n",2)<0)return -1;
            s->edit[s->len]=0;memcpy(s->lines[w&(WBG_INPUT_LINES-1)],s->edit,s->len+1);
            s->len=0;s->skip_lf=c=='\r';atomic_store(&s->rx_w,w+1);
        }else if(c==8 || c==127){
            if(s->len){--s->len;if(echo_text(s,"\b \b",3)<0)return -1;}
        }else{
            if(c<32 || c>=127)return abort_game(s,WBG_BAD_INPUT);
            if(s->len>=WBG_LINE)return abort_game(s,WBG_INPUT_LIMIT);
            s->edit[s->len++]=(char)c;if(echo_text(s,(const char*)&c,1)<0)return -1;
        }
    }
    return 1;
}
int wbg_prefeed(wb_game_io *s,uint64_t owner,const uint8_t *p,size_t n,int skip_start_lf){
    if(!s || !owner || owner!=s->owner)return -2;
    if(atomic_load(&s->state)!=WBG_ACTIVE)return -1;
    s->skip_lf=!!skip_start_lf;
    return feed(s,p,n);
}
int wbg_tick(wb_game_io *s,uint64_t owner,int admitted,void *io,wbg_read_fn rd,wbg_write_fn wr){
    if(!s || !owner || s->owner!=owner)return -2;
    unsigned state=atomic_load(&s->state);
    if(state!=WBG_ACTIVE && state!=WBG_DONE)return -1;
    if(!admitted)return abort_game(s,WBG_ACCESS_REVOKED);
    if(!rd||!wr)return abort_game(s,WBG_DISCONNECT);
    if(state!=WBG_DONE){
        uint8_t p[64];int k=rd(io,p,sizeof p);
        if(k==-2)return abort_game(s,WBG_EOF);
        if(k<0 || (size_t)k>sizeof p)return abort_game(s,WBG_DISCONNECT);
        if(feed(s,p,(size_t)k)<0)return -1;
    }
    unsigned r=atomic_load(&s->tx_r),w=atomic_load(&s->tx_w);
    int is_game=r!=w;
    if(!is_game){r=s->echo_r;w=s->echo_w;}
    if(r!=w){
        unsigned cap=is_game?WBG_TX:WBG_ECHO,off=r&(cap-1),n=w-r;
        if(n>cap-off)n=cap-off;
        if(n>256)n=256;
        int k=wr(io,(is_game?s->tx:s->echo)+off,n);
        if(k<0 || (unsigned)k>n)return abort_game(s,WBG_DISCONNECT);
        if(is_game)atomic_store(&s->tx_r,r+(unsigned)k);
        else {s->echo_r+=(unsigned)k;if(s->echo_r==s->echo_w)atomic_store(&s->echo_owed,0);}
        return 1;
    }
    return state==WBG_DONE?0:1;
}
