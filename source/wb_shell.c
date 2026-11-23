/* Deliberately NOT a system shell. No process execution, command expansion,
 * redirection, pipelines, device mounts or process-global working directory. */
#include "wb_shell.h"
#include "wb_app_remove_policy.h"
#include "wb_crash_limit.h"
#include <string.h>

#define ROOT "ux0:/"
#define INBOX_DIR "ux0:/VITA-POC"
#define INCOMING INBOX_DIR "/"
#define NWORDS 12

static int say(wb_out *out,const char *s){return wb_out_puts(out,s)<0?-1:0;}
static int done(int rc){return rc<0?-1:0;}
static int eq(const char *a,const char *b){return !strcmp(a,b);}
void wb_shell_init(wb_shell_engine *s){if(s)memcpy(s->cwd,ROOT,sizeof ROOT);}
int wb_shell_prompt(const wb_shell_engine *s,wb_out *out){
    return !s || wb_out_printf(out,"%s> ",s->cwd)<0 ? -1 : 0;
}

/* Split spaces and quotes only. Tabs may delimit arguments, never become
 * pathname bytes. No backslash escapes/expansion or command separators. */
static int split(const char *line,char buf[WB_SH_LINE+1],char *v[NWORDS]){
    size_t n=0,w=0;int count=0;char quote=0;bool word=false;
    while(n<=WB_SH_LINE && line[n])++n;
    if(n>WB_SH_LINE)return -1;
    for(size_t i=0;i<n;i++){
        unsigned char ch=(unsigned char)line[i];
        if(ch<32 && ch!='\t') return -1;
        if(ch==127 || ch>=128 || ch=='\\')return -1;
        if(!quote && (ch==' '||ch=='\t')){
            if(word){buf[w++]=0;word=false;}
            continue;
        }
        if(!word){
            if(count==NWORDS)return -1;
            v[count++]=buf+w;word=true;
        }
        if(!quote && (ch=='\''||ch=='"')){quote=(char)ch;continue;}
        if(quote && ch==(unsigned char)quote){quote=0;continue;}
        if(ch=='\t' || (!quote && strchr(";&|`$<>",ch)))return -1;
        buf[w++]=(char)ch;
    }
    buf[w]=0;
    return quote?-1:count;
}

static int resolve(const char *cwd,const char *input,char out[WB_SH_PATH]){
    if(!input || !*input)return 0;
    const char *p=input;
    /* Only the literal absolute /inbox component selects this shorthand.
     * Keep a physical cwd and use the usual bounds, type, and policy checks.
     * An explicitly alias-qualified path must not walk above its anchor. */
    size_t floor=sizeof ROOT-1;
    if(!strncmp(p,"/inbox",6) && (!p[6] || p[6]=='/')){
        p+=6;if(*p=='/')++p;
        memcpy(out,INBOX_DIR,sizeof INBOX_DIR);floor=sizeof INBOX_DIR-1;
    }else if(!strncmp(p,ROOT,sizeof ROOT-1)){p+=sizeof ROOT-1;memcpy(out,ROOT,sizeof ROOT);}
    else if(*p=='/'){++p;memcpy(out,ROOT,sizeof ROOT);}
    else if(!strncmp(p,"ux0:data",8) && (!p[8]||p[8]=='/')){
        /* Explicit legacy spelling used by the existing WB core. */
        p+=4;memcpy(out,ROOT,sizeof ROOT);
    }else memcpy(out,cwd,strlen(cwd)+1);
    size_t w=strlen(out);
    while(*p){
        const char *end=strchr(p,'/');size_t len=end?(size_t)(end-p):strlen(p);
        if(!len || len>100)return 0;
        if(len==1 && *p=='.'){} /* current */
        else if(len==2 && p[0]=='.' && p[1]=='.'){
            if(w==floor && floor!=sizeof ROOT-1)return 0;
            while(w>floor && out[w-1]!='/')--w;
            if(w>floor)--w;
            out[w]=0;
        }else{
            for(size_t j=0;j<len;j++)
                if((unsigned char)p[j]<32 || (unsigned char)p[j]>=127 || strchr(":\\\"*?<>|",p[j]))return 0;
            if(p[len-1]=='.'||p[len-1]==' ')return 0;
            if(w+(w>sizeof ROOT-1?1u:0u)+len>=WB_SH_PATH)return 0;
            if(w>sizeof ROOT-1)out[w++]='/';
            memcpy(out+w,p,len);w+=len;out[w]=0;
        }
        if(!end)break;
        p=end+1;
    }
    return 1;
}

static int oneof(const char *s,const char *const *values,size_t n){
    for(size_t i=0;i<n;i++)if(eq(s,values[i]))return 1;
    return 0;
}
/* Completion only consumes the public, typed "ls" view. No raw directory
 * handles, command dispatch, global cache, or printing directory data. */
typedef struct {
    const char *leaf; int dirs,game;
    unsigned hits; size_t used; char row[104],common[104];
} matches;

static void candidate(matches *m,const char *name){
    if(strncmp(name,m->leaf,strlen(m->leaf)))return;
    if(!m->hits)strcpy(m->common,name);
    else {size_t k=0;while(m->common[k]&&m->common[k]==name[k])++k;m->common[k]=0;}
    ++m->hits;
}
static int match_rows(void *ctx,const char *p,size_t n){
    matches *m=ctx;
    for(size_t i=0;i<n;i++){
        unsigned char ch=(unsigned char)p[i];
        if(ch!='\n'){
            if(m->used==sizeof m->row-1 || ch<32 || ch>=127)return -1;
            m->row[m->used++]=(char)ch;continue;
        }
        size_t z=m->used; m->row[z]=0;
        int dir=z&&m->row[z-1]=='/';size_t len=z-(size_t)dir;
        if(!len||len>100||m->row[0]=='.'||m->row[0]==' '||
           m->row[len-1]==' '||m->row[len-1]=='.')return -1;
        if(strspn(m->row,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._()-")!=len)return -1;
        if((!m->dirs||dir)&&(!m->game||eq(m->row,"tictactoe_ai.py")))candidate(m,m->row);
        m->used=0;
    }
    return 0;
}
static int discard_row(void *ctx,const char *p,size_t n){(void)ctx;(void)p;(void)n;return 0;}
bool wb_shell_complete(const wb_shell_engine *s,const char *line,const wb_shell_ops *ops,char out[WB_SH_LINE]){
    static const char *const commands[]={
        "app","app-approve","app-install","apply-core","apply-return","bye","cat","cd","close","deploy","df","diag","doctor","exit","ext",
        "font","get","hash-selftest","help","inspect","install","launch","ls","mkdir","mv","pending","photo-export",
        "plan","promote","ps","put","pwd","quit","r1-auto-status","r1-notice","r1-review","r1-signed","r1-status","reload","rm","rollback","s1-check","send",
        "settings","shot","stat","status","test","timeline","update","updater","ver","wake","wb","wb-status",
#ifdef WB_GAME_FEATURE
        "python3",
#endif
    };
    static const char *const paths[]={"ls","cd","cat","stat","inspect","plan","app-install","install",
        "deploy","photo-export","rm","mv","mkdir","get"};
    if(!s||!line||!ops||!out)return false;
    size_t size=0,beg=0;char quote=0;
    while(size<WB_SH_LINE && line[size]){
        char c=line[size];
        if((unsigned char)c<32 || (unsigned char)c>=127)return false;
        if(!quote && c==' ')beg=size+1;
        else if(!quote && (c=='\'' || c=='"'))quote=c;
        else if(quote==c)quote=0;
        ++size;
    }
    if(size>=WB_SH_LINE-1||beg==size)return false;
    /* Do not rewrite completed quotes or mixed quoting. The current token
     * may start with an open quote; all earlier tokens must parse cleanly. */
    const char *token=line+beg;
    if(quote){if(*token!=quote)return false;++token;}
    if(strpbrk(token,"'\"")||!*token)return false;
    char scratch[WB_SH_LINE+1],parsed[WB_SH_LINE+1],*words[NWORDS];
    memcpy(scratch,line,size);size_t end=size;
    if(quote)scratch[end++]=quote;
    scratch[end]=0;int argc=split(scratch,parsed,words);
    if(argc<1)return false;
    matches m={0};m.leaf=token;size_t dirlen=0;
    if(argc==1){
        if(quote)return false;
        for(size_t i=0;i<sizeof commands/sizeof *commands;i++)candidate(&m,commands[i]);
    }else{
        const char *cmd=words[0];bool game=eq(cmd,"python3");
#ifndef WB_GAME_FEATURE
        if(game)return false;
#endif
        int operand=1;
        if(eq(cmd,"ls")&&argc>2&&eq(words[1],"-l"))++operand;
        if(operand<argc-1 && eq(words[operand],"--") && (eq(cmd,"cd")||eq(cmd,"ls")||eq(cmd,"cat")))++operand;
        if((eq(cmd,"app")&&(eq(words[1],"plan")||eq(words[1],"install")))||
           (eq(cmd,"update")&&(eq(words[1],"plan")||eq(words[1],"stage"))))++operand;
        else if(!game&&!oneof(cmd,paths,sizeof paths/sizeof *paths))return false;
        if(argc-1!=operand&&!(eq(cmd,"mv")&&argc==3))return false;
        if(game&&(argc!=2||quote||strcmp(s->cwd,INBOX_DIR)||strchr(token,'/')))return false;
        const char *slash=strrchr(token,'/');char dir[WB_SH_PATH],canonical[WB_SH_PATH];
        dirlen=slash?(size_t)(slash+1-token):0;
        if(dirlen>=sizeof dir||!ops->list||!ops->isdir)return false;
        if(dirlen){memcpy(dir,token,dirlen);dir[dirlen]=0;}else strcpy(dir,".");
        if(!resolve(s->cwd,dir,canonical))return false;
        wb_out quiet={NULL,discard_row},sink={&m,match_rows};
        m.leaf=token+dirlen;m.dirs=eq(cmd,"cd");m.game=game;
        if(ops->isdir(ops->ctx,canonical,&quiet)!=0 || ops->list(ops->ctx,canonical,false,&sink)!=0 || m.used)return false;
        if(dirlen==1 && token[0]=='/' && !strncmp("inbox/",m.leaf,strlen(m.leaf)) &&
           ops->isdir(ops->ctx,INBOX_DIR,&quiet)==0)candidate(&m,"inbox/");
    }
    if(!m.hits||!m.common[0])return false;
    /* Preserve the already typed path prefix. Quote a single token containing
     * spaces, never a whole command. A unique directory with an opening quote
     * can be entered immediately; remove its closing quote to continue typing. */
    size_t z=strlen(m.common),w=beg;
    bool quoted=quote||strchr(m.common,' ')!=NULL;
    size_t need=w+(quoted?1u:0u)+dirlen+z+(quoted&&m.hits==1?1u:0u)+(argc==1&&m.hits==1?1u:0u);
    if(need>=WB_SH_LINE)return false;
    memcpy(out,line,beg);
    if(quoted)out[w++]=quote?quote:'"';
    memcpy(out+w,token,dirlen);w+=dirlen;memcpy(out+w,m.common,z);w+=z;
    if(quoted&&m.hits==1)out[w++]=quote?quote:'"';
    if(argc==1&&m.hits==1)out[w++]=' ';
    out[w]=0;return strcmp(line,out)!=0;
}

/* Encode quoted spaces for the existing fixed-operand parser so "a b" does
 * not become two arguments or a new option. 0x1f cannot come from split(). */
static int parse_core(int n,char **v,wb_cmd *c){
    char wire[WB_SH_LINE+1];size_t w=0;
    for(int i=0;i<n;i++){
        size_t z=strlen(v[i]);if(!z||w+(i?1u:0u)+z>WB_SH_LINE)return 0;
        if(i)wire[w++]=' ';
        for(size_t j=0;j<z;j++)wire[w++]=v[i][j]==' '?31:v[i][j];
    }
    wire[w]=0;if(!wb_cmd_parse(wire,w,c))return 0;
    for(int i=0;i<c->argc;i++)for(char *p=c->argv[i];*p;p++)if(*p==31)*p=' ';
    return 1;
}

static bool ishex(const char *s){return strlen(s)==64 && strspn(s,"0123456789abcdef")==64;}
static int safe_core_args(wb_cmd *c){
    if(c->force||c->any_title||c->promote_now||c->no_period||c->install_after)return 0;
    if((c->keep_stage||c->no_reload||*c->sha256) && c->kind!=WB_CMD_INSTALL)return 0;
    switch(c->kind){
    case WB_CMD_INSTALL:return c->argc==1 && ishex(c->sha256);
    case WB_CMD_PLAN:case WB_CMD_APP_INSTALL:return c->argc==1;
    case WB_CMD_GET:case WB_CMD_PUT:case WB_CMD_NONE:case WB_CMD_BYE:return 0;
    case WB_CMD_EXT:return 1; /* checked on exact payload verb below */
    case WB_CMD_VER:case WB_CMD_STATUS:case WB_CMD_SHOT:case WB_CMD_RELOAD:
    case WB_CMD_ROLLBACK:case WB_CMD_PENDING:case WB_CMD_R1_STATUS:
    case WB_CMD_APPLY_CORE:case WB_CMD_PROMOTE:case WB_CMD_S1_CHECK:
    case WB_CMD_HASH_SELFTEST:return c->argc==0;
    case WB_CMD_DF:return c->argc==0 || (c->argc==1 && c->argv[0][0] &&
                         strspn(c->argv[0],"0123456789")==strlen(c->argv[0]));
    case WB_CMD_DEPLOY:case WB_CMD_INSPECT:return c->argc==1;
    case WB_CMD_PHOTO_EXPORT:return c->argc==2&&ishex(c->argv[1]);
    case WB_CMD_TIMELINE:return !c->argc||(c->argc==1&&eq(c->argv[0],"selftest"));
    case WB_CMD_LAUNCH:return c->argc==3;
    case WB_CMD_APPLY_RETURN:return c->argc==1&&strlen(c->argv[0])==32&&strspn(c->argv[0],"0123456789ABCDEF")==32;
    default:return 0;
    }
}
/* Only native spelling conversion for a verified path, not extra permission.
 * Interactive filesystem writes via ext are restricted to incoming children. */
static int arg_path(wb_shell_engine *s,char *arg,bool write){
    char tmp[WB_SH_PATH];
    if(!resolve(s->cwd,arg,tmp))return 0;
    if(write && (strncmp(tmp,INCOMING,sizeof INCOMING-1) || !tmp[sizeof INCOMING-1])) return 0;
    if(!strncmp(tmp,"ux0:/data",9) && (!tmp[9] || tmp[9]=='/'))
        memmove(tmp+4,tmp+5,strlen(tmp+5)+1);
    memcpy(arg,tmp,strlen(tmp)+1);return 1;
}
/* Native core produces text, including some filenames controlled by other
 * software. Escape any terminal control before presenting it to a PC. */
static int clean_write(void *opaque,const char *src,size_t n){
    wb_out *out=opaque;char tmp[128];size_t used=0;
    for(size_t i=0;i<n;i++){
        unsigned char c=(unsigned char)src[i];
        if(c=='\r')continue;
        tmp[used++]=(c=='\n'||c=='\t'||(c>=32 && c<127))?(char)c:'?';
        if(used==sizeof tmp){if(out->write(out->ctx,tmp,used)<0)return -1;used=0;}
    }
    return used?out->write(out->ctx,tmp,used):0;
}

static int core_raw(const wb_shell_ops *ops,const wb_cmd *c,wb_out *out){
    wb_out text={out,clean_write};
    if(!ops->core_exec)return say(out,"ERR Workbench service unavailable\n")<0?-1:1;
    return ops->core_exec(ops->ctx,c,&text);
}
#include "wb_shell_settings.inc"

static const char *topic_help(const char *t){
    if(eq(t,"diag"))return "diag crashes [--limit N] (1..32, default 10): latest ux0:data psp2core file metadata only. Times are device-local. No dump is opened.\n";
    if(eq(t,"settings"))return WB_SETTINGS_HELP;
    if(eq(t,"font"))return
        "font | font set FAMILY SCALE GAP_X GAP_Y | font reset | font license\n"
        "FAMILY: classic or jetbrains. SCALE: 1..3 (integer). Blank pixels: GAP_X 0..4, GAP_Y 2..10.\n"
        "Example: font set classic 2 2 8 (extra space between lines; same font).\n"
        "Vita display only. Saved across app restarts. Default: classic 2 2 6. SSH window unchanged.\n";
    if(eq(t,"files"))return
        "pwd | cd [DIR] | ls [-l] [PATH] | cat FILE | stat PATH | mkdir PATH | mv OLD NEW | rm PATH\n"
        "/inbox = ux0:/VITA-POC for shell paths; pwd shows the native path.\n"
        "File stream: put ABS BYTES sha256=HEX | get ABS (terminal frames; help transfer).\n"
        "rm removes one file or an empty directory; no recursive delete. Writes only in incoming.\n";
    if(eq(t,"transfer"))return
        "put ABS BYTES sha256=HEX (send is an alias); get ABS. Use the 5090 framed terminal sender/receiver for PC files.\n"
        "After a verified upload: photo-export IMAGE SHA256 to import once into Photos. Do not retry an uncertain receipt.\n";
    if(eq(t,"update"))return
        "update plan VPK | update stage VPK sha256=HEX | update apply | pending | s1-check\n"
        "update stage queues verified content without applying the queued core. update apply is the attended updater; SSH will drop.\n"
        "Owner-approved return: r1-review (read only) | r1-status | apply-return NONCE.\n"
        "r1-auto-status shows locally enrolled signed-update consent; r1-signed R S requires it. Only local SELECT revokes standing consent.\n"
        "r1-notice MANIFEST posts the verified update for the owner's local approval after disconnect; it does not authorize or apply.\n"
        "updater check: read-only identity and registration check of INAP00019 (no promotion or launch).\n"
        "Payload: deploy SUPRX (approved payload bytes only) | reload | rollback. No --force.\n";
    if(eq(t,"ps"))return "ps | app running: read-only bounded AppMgr-started-app snapshot; foreground remains unknown.\n";
    if(eq(t,"wake"))return
        "wake probe JOBID | wake probe-status: finite 120s background diagnostic; approved Lifecycle 01.02 only.\n"
        "Probe data is NOT authenticated receiver readiness. close wb remains disabled until a real receiver is verified.\n";
    if(eq(t,"app"))return
        "app list | app running (alias: ps) | app plan VPK [CASE] | app install VPK | launch TITLE CASE JOB\n"
        "app status TITLE | app uninstall-plan TITLE | app uninstall TITLE TOKEN (same terminal, 120s)\n"
        "app status VSSH00001 | app uninstall VSSH00001 (only approved ssh-vita 1.4.2)\n"
        "list shows approvals, not installed apps. plan checks actual stored bytes without staging. install never launches.\n";
    if(eq(t,"test"))return
        "test run CASE JOB | test result CASE JOB. Make JOB unique; reconnect after launch and check ver/run.\n"
        "result checks job, title, registered case/build and assertion; a launch reply alone is never PASS.\n";
    if(eq(t,"status"))return
        "doctor | ver | status | pending | timeline [selftest] | df [required-bytes] | hash-selftest | inspect FILE | shot\n"
        "wb status (wb-status) is a paired terminal diagnostic of live focus, link, queue and standing state. Lock state unavailable.\n"
        "close wb requires a verified WAKE receiver (unavailable in this version). exit only closes this SSH shell.\n"
        "Payload: ext hello/sys/features/tick/ls/stat/mkdir/mv/rm. Terminal rejects unknown verbs/flags.\n";
    return "ERR help topic: files transfer update app test status font settings diag\n";
}

int wb_shell_run(wb_shell_engine *s,const char *line,wb_out *out,const wb_shell_ops *ops){
    if(!s||!line||!out||!out->write||!ops)return -1;
    size_t count=0;while(count<=WB_SH_LINE && line[count])count++;
    if(count>WB_SH_LINE)return say(out,"ERR command too long\n");
    const char *lead=line;while(*lead==' '||*lead=='\t')lead++;
    size_t k=strcspn(lead," \t");
    if((k==3&&!strncmp(lead,"put",3))||(k==4&&!strncmp(lead,"send",4))||(k==3&&!strncmp(lead,"get",3)))
        return say(out,"ERR transfer syntax: put ABS BYTES sha256=HEX | get ABS; use the framed SSH terminal session\n");
    char buf[WB_SH_LINE+1],*v[NWORDS];int n=split(line,buf,v);
    if(n<0)return say(out,"ERR syntax: use one bounded ASCII command; no pipes, redirects or expansions\n");
    if(!n)return 0;
    const char *verb=v[0];
    if(eq(verb,"exit")||eq(verb,"quit")||eq(verb,"bye")){
        if(n!=1)return say(out,"ERR usage: exit\n");
        return say(out,"Bye.\n")<0?-1:1;
    }
    if(eq(verb,"help")||eq(verb,"?")){
        if(n==2)return say(out,topic_help(v[1]));
        if(n!=1)return say(out,"ERR usage: help [files|transfer|update|app|ps|wake|test|status|font|settings|diag]\n");
        return say(out,
            "pwd | cd [DIR] | ls [-l] [PATH] | cat FILE | ps | app running | exit\n"
#ifdef WB_GAME_FEATURE
            "Game: cd VITA-POC, then python3 tictactoe_ai.py (trusted file only). Game exit closes this channel.\n"
#endif
            "Paths use ux0:/ or /; try cd /inbox. Tab completes commands and approved paths; Enter runs. No OS shell.\n"
            "doctor | help files | help transfer | help update | help app | help test | help status | help font | help settings | help diag\n"
            "Workbench commands include ver status df timeline pending inspect plan shot photo-export\n"
            "app-install launch install apply-core apply-return r1-notice r1-review r1-status promote reload rollback deploy\n");
    }
    if(eq(verb,"settings"))return wbsh_settings(ops,n,v,out);
    if(eq(verb,"pwd"))return n==1?done(wb_out_printf(out,"%s\n",s->cwd)):say(out,"ERR usage: pwd\n");
    if(eq(verb,"ls")||eq(verb,"cd")||eq(verb,"cat")){
        char p[WB_SH_PATH];int i=1;bool ls=eq(verb,"ls"),cd=eq(verb,"cd"),lng=false;
        if(ls && i<n && eq(v[i],"-l")){lng=true;i++;}
        if(i<n && eq(v[i],"--"))++i;
        else if(i<n && v[i][0]=='-')return say(out,"ERR unsupported option; use -- before a dash-prefixed name\n");
        if(n-i>1 || (!cd&&!ls&&n-i!=1))return say(out,"ERR usage: ls [-l] [PATH] | cd [DIR] | cat FILE\n");
        if(!resolve(s->cwd,i<n?v[i]:cd?ROOT:".",p))return say(out,"ERR invalid ux0 path\n");
        if(cd){
            if(!ops->isdir)return say(out,"ERR directory service unavailable\n");
            int rc=ops->isdir(ops->ctx,p,out);
            if(rc==0)memcpy(s->cwd,p,strlen(p)+1);
            return done(rc);
        }
        if(ls&&ops->list)return done(ops->list(ops->ctx,p,lng,out));
        if(!ls&&ops->cat)return done(ops->cat(ops->ctx,p,out));
        return say(out,"ERR filesystem service unavailable\n");
    }
    wb_cmd c;
    if(eq(verb,"wb-status")||eq(verb,"wb")){
        if(eq(verb,"wb")?(n!=2||!eq(v[1],"status")):n!=1)return say(out,"ERR wb-status usage\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_WB_STATUS;
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"r1-auto-status") || eq(verb,"r1-signed")){
        bool signed_req=eq(verb,"r1-signed");
        if((signed_req && (n!=3||!ishex(v[1])||!ishex(v[2]))) || (!signed_req&&n!=1))
            return say(out,signed_req?"ERR r1-signed usage\n":"ERR r1-auto usage\n");
        memset(&c,0,sizeof c);c.kind=signed_req?WB_CMD_TERM_R1_SIGNED:WB_CMD_TERM_R1_AUTO_STATUS;
        if(signed_req){c.argc=2;strcpy(c.argv[0],v[1]);strcpy(c.argv[1],v[2]);}
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"ps") || (eq(verb,"app") && n>=2 && eq(v[1],"running"))){
        if((eq(verb,"ps") && n!=1) || (eq(verb,"app") && n!=2 && n!=3))
            return say(out,"ERR app-running usage: ps | app running [TITLEID]\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_APP_RUNNING;
        if(n==3&&eq(v[2],"all")){
            c.argc=1;memcpy(c.argv[0],"all",4);
            return done(core_raw(ops,&c,out));
        }
        if(n==3){
            const size_t len=strlen(v[2]);
            if(len!=9)return say(out,"ERR app-running needs a 9-character title id\n");
            for(size_t i=0;i<9;++i)
                if(!((v[2][i]>='A'&&v[2][i]<='Z')||(v[2][i]>='0'&&v[2][i]<='9')))
                    return say(out,"ERR app-running needs a 9-character title id\n");
            c.argc=1;memcpy(c.argv[0],v[2],len+1);
        }
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"wake")){
        memset(&c,0,sizeof c);
        if(n==2 && eq(v[1],"probe-status"))c.kind=WB_CMD_TERM_WAKE_PROBE_STATUS;
        else if(n==3 && eq(v[1],"probe")){
            size_t z=strlen(v[2]);
            if(!z || z>32 || strspn(v[2],"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")!=z)
                return say(out,"ERR wake-probe job-id\n");
            c.kind=WB_CMD_TERM_WAKE_PROBE;c.argc=1;memcpy(c.argv[0],v[2],z+1);
        }else return say(out,"ERR usage: wake probe JOBID | wake probe-status\n");
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"close")){
        if(n!=2||!eq(v[1],"wb"))return say(out,"ERR close-wb usage: close wb\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_CLOSE_WB;
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"r1-review")){
        if(n!=1)return say(out,"ERR r1-review usage\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_R1_REVIEW;
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"r1-notice")){
        if(n!=2)return say(out,"ERR r1-notice usage\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_R1_NOTICE;c.argc=1;
        strcpy(c.argv[0],v[1]);return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"diag")){
        if((n!=2&&n!=4)||!eq(v[1],"crashes")||
           (n==4&&(!eq(v[2],"--limit")||!wb_crash_limit(v[3]))))
            return say(out,"ERR crash-index usage\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_CRASH_INDEX;
        if(n==4){c.argc=1;strcpy(c.argv[0],v[3]);}
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"updater")){
        if(n!=2 || !eq(v[1],"check"))return say(out,"ERR usage: updater check\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_UPDATER_CHECK;
        return done(core_raw(ops,&c,out));
    }
    if(eq(verb,"font")){
        if(n!=1 && !(n==2 && (eq(v[1],"reset")||eq(v[1],"license"))) &&
           !(n==6 && eq(v[1],"set")))
            return say(out,"ERR usage: font | font set FAMILY SCALE GAP_X GAP_Y | font reset | font license\n");
        memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_FONT;c.argc=n-1;
        for(int i=1;i<n;i++){
            size_t len=strlen(v[i]);if(!len||len>=sizeof c.argv[0])return say(out,"ERR font-value; see help font\n");
            memcpy(c.argv[i-1],v[i],len+1);
        }
        return done(core_raw(ops,&c,out));
    }
    /* Named tasks use the same checked core functions. Never parse user text a
     * second time or join it into an executable host/shell command. */
    if(eq(verb,"doctor")){
        if(n!=1)return say(out,"ERR usage: doctor\n");
        static const wb_cmd_kind checks[]={WB_CMD_VER,WB_CMD_DF,WB_CMD_PENDING,WB_CMD_STATUS,WB_CMD_TIMELINE};
        for(size_t i=0;i<sizeof checks/sizeof checks[0];i++){
            memset(&c,0,sizeof c);c.kind=checks[i];int rc=core_raw(ops,&c,out);
            if(rc!=0)return done(rc);
        }
        return 0;
    }
    if(eq(verb,"app")||eq(verb,"test")||eq(verb,"update")){
        if(eq(verb,"app")&&n>=3&&wb_remove_id(v[2])&&
           (eq(v[1],"status")||eq(v[1],"uninstall-plan")||eq(v[1],"uninstall"))){
            bool commit=eq(v[1],"uninstall");
            if((commit&&(n!=4||!wb_remove_hex(v[3])))||(!commit&&n!=3))
                return say(out,"ERR app-uninstall: plan then commit exact TITLE TOKEN\n");
            memset(&c,0,sizeof c);
            c.kind=commit?WB_CMD_TERM_USER_REMOVE:(eq(v[1],"status")?WB_CMD_TERM_USER_STATUS:WB_CMD_TERM_USER_PLAN);
            c.argc=n-2;strcpy(c.argv[0],v[2]);if(commit)strcpy(c.argv[1],v[3]);return done(core_raw(ops,&c,out));
        }
        if(eq(verb,"app")&&n>=2&&(eq(v[1],"status")||eq(v[1],"uninstall"))){
            if(n!=3||!eq(v[2],"VSSH00001"))return say(out,"ERR app-target: VSSH00001 only\n");
            memset(&c,0,sizeof c);
            c.kind=eq(v[1],"status")?WB_CMD_TERM_SSH_VITA_STATUS:WB_CMD_TERM_SSH_VITA_UNINSTALL;
            c.argc=1;strcpy(c.argv[0],"VSSH00001");return done(core_raw(ops,&c,out));
        }
        if(eq(verb,"app")&&n==2&&eq(v[1],"list")){
            memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_APP_LIST;return done(core_raw(ops,&c,out));
        }
        if(eq(verb,"app")&&n==5&&eq(v[1],"approve")){
            /* app approve VPK R S -- owner-signed, install-only runtime row. */
            memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_APP_APPROVE;c.argc=3;
            for(int k=0;k<3;++k){
                size_t len=strlen(v[2+k]);
                if(!len||len>=sizeof c.argv[k]||v[2+k][0]=='-')return say(out,"ERR invalid app-approve operand\n");
                memcpy(c.argv[k],v[2+k],len+1);
            }
            if(!arg_path(s,c.argv[0],false))return say(out,"ERR package must be in VITA-POC\n");
            if(strlen(c.argv[1])!=64||strlen(c.argv[2])!=64||
               strspn(c.argv[1],"0123456789abcdef")!=64||strspn(c.argv[2],"0123456789abcdef")!=64)
                return say(out,"ERR app-approve needs two scalar hex values\n");
            return done(core_raw(ops,&c,out));
        }
        if(eq(verb,"app")&&(n==3||n==4)&&eq(v[1],"plan")){
            memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_APP_PLAN;c.argc=n-2;
            for(int k=0;k<c.argc;++k){
                size_t len=strlen(v[2+k]);if(!len||len>=sizeof c.argv[k]||v[k+2][0]=='-')return say(out,"ERR invalid app-plan operand\n");
                memcpy(c.argv[k],v[2+k],len+1);
            }
            if(!arg_path(s,c.argv[0],true))return say(out,"ERR package must be in VITA-POC\n");
            return done(core_raw(ops,&c,out));
        }
        if(eq(verb,"app")&&n==3&&eq(v[1],"install")){
            v[0]="app-install";v[1]=v[2];n=2;
        } else if(eq(verb,"update")&&n==3&&eq(v[1],"plan")){
            v[0]="plan";v[1]=v[2];n=2;
        } else if(eq(verb,"update")&&n==4&&eq(v[1],"stage")){
            v[0]="install";v[1]=v[2];v[2]=v[3];n=3;
        } else if(eq(verb,"update")&&n==2&&eq(v[1],"apply")){
            v[0]="apply-core";n=1;
        } else if(eq(verb,"test")&&n==4&&(eq(v[1],"run")||eq(v[1],"result"))){
            for(int i=2;i<4;i++){
                size_t len=strlen(v[i]);if(!len||len>63||strspn(v[i],"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")!=len)
                    return say(out,"ERR invalid case or job\n");
            }
            if(eq(v[1],"result")){
                memset(&c,0,sizeof c);c.kind=WB_CMD_TERM_RESULT;c.argc=2;
                strcpy(c.argv[0],v[2]);strcpy(c.argv[1],v[3]);return done(core_raw(ops,&c,out));
            }
            v[0]="launch";v[1]="INAP00020"; /* only approved TestApp may run jobs */
        } else return say(out,"ERR invalid task or operands; type help app, help test or help update\n");
    }
    if(!parse_core(n,v,&c)||!safe_core_args(&c))return say(out,"ERR invalid or disallowed Workbench command/options\n");
    if(c.kind==WB_CMD_EXT){
        const char *x=c.name;int first=0;
        if(eq(x,"ext")){if(!c.argc)return say(out,"ERR usage: ext VERB\n");x=c.argv[0];first++;}
        const char *const zero[]={"hello","sys","features","tick"};
        if(oneof(x,zero,sizeof zero/sizeof zero[0])){
            if(c.argc!=first)return say(out,"ERR unexpected argument\n");
        }else if(eq(x,"ls")){
            char p[WB_SH_PATH];
            if(c.argc-first!=1||!resolve(s->cwd,c.argv[first],p))return say(out,"ERR usage: ext ls DIR\n");
            return ops->list?done(ops->list(ops->ctx,p,false,out)):say(out,"ERR listing unavailable\n");
        }else if(eq(x,"stat")||eq(x,"rm")||eq(x,"mv")||eq(x,"mkdir")){
            if(c.argc-first!=(eq(x,"mv")?2:1))return say(out,"ERR invalid file operands\n");
            for(int i=first;i<c.argc;i++)
                if(!arg_path(s,c.argv[i],!eq(x,"stat")))return say(out,"ERR path denied\n");
        }else return say(out,"ERR unknown command; type help\n");
    }else if(c.kind==WB_CMD_PLAN||c.kind==WB_CMD_INSPECT||c.kind==WB_CMD_INSTALL||
            c.kind==WB_CMD_APP_INSTALL||c.kind==WB_CMD_PHOTO_EXPORT||c.kind==WB_CMD_DEPLOY){
        if(!arg_path(s,c.argv[0],false))return say(out,"ERR invalid ux0 path\n");
        const char *const public_diag[]={
            "ux0:data/INAP00018/install.log","ux0:data/INAP00018/startup.log",
            "ux0:data/INAP00018/run.log","ux0:data/INAP00018/timeline.txt","ux0:data/INAP00018/shot.bmp",
            "ux0:data/INAP00018/testapp/result.txt"};
        if(strncmp(c.argv[0],INCOMING,sizeof INCOMING-1) &&
           !(c.kind==WB_CMD_INSPECT&&oneof(c.argv[0],public_diag,sizeof public_diag/sizeof public_diag[0])))
            return say(out,"ERR path denied\n");
        /* Staging a core should not also hot-load a package member. The WBQ2
         * updater verifies all stage members when the owner chooses apply. */
        if(c.kind==WB_CMD_INSTALL)c.no_reload=true;
        if(c.kind==WB_CMD_DEPLOY)c.kind=WB_CMD_TERM_DEPLOY;
    }
    return done(core_raw(ops,&c,out));
}
