/* Included at the end of wb_shell.c.
 * Workbench 2.0 compound commands: CMD ; CMD && CMD | FILTER
 * Not a system shell: each segment is still one checked Workbench command,
 * and only the built-in text filters below may follow a pipe. */
#ifdef WB_SHELL2
#include <stdio.h>
#include <stdlib.h>
enum { CAP_BYTES = 65536, MAX_SEGS = 8, MAX_STAGES = 6, MAX_LINES = 4096 };
typedef struct { char *b; size_t n; bool over; } capbuf;
static int cap_write(void *ctx,const char *p,size_t n){
    capbuf *c=ctx;
    if(n>CAP_BYTES-c->n){c->over=true;n=CAP_BYTES-c->n;}
    memcpy(c->b+c->n,p,n);c->n+=n;return 0;
}
static void cap_put(capbuf *c,const char *p){(void)cap_write(c,p,strlen(p));}
static void cap_span(capbuf *c,const char *p,size_t n){(void)cap_write(c,p,n);(void)cap_write(c,"\n",1);}
static char lower_ch(char c){return (c>='A'&&c<='Z')?(char)(c-'A'+'a'):c;}
static bool contains(const char *h,size_t hn,const char *nd,bool icase){
    const size_t m=strlen(nd);
    if(!m)return true;
    for(size_t i=0;i+m<=hn;i++){
        size_t k=0;
        while(k<m && (icase?lower_ch(h[i+k])==lower_ch(nd[k]):h[i+k]==nd[k]))k++;
        if(k==m)return true;
    }
    return false;
}
typedef struct { const char *p; size_t n; } span;
static size_t lines_of(const capbuf *in,span *L,size_t max){
    size_t count=0,start=0;
    for(size_t i=0;i<=in->n && count<max;i++){
        if(i==in->n || in->b[i]=='\n'){
            if(i==in->n && i==start)break;
            L[count].p=in->b+start;L[count].n=i-start;count++;start=i+1;
        }
    }
    return count;
}
static int cmp_span(const void *a,const void *b){
    const span *x=a,*y=b;const size_t m=x->n<y->n?x->n:y->n;
    const int r=memcmp(x->p,y->p,m);
    return r?r:(x->n<y->n?-1:x->n>y->n?1:0);
}
static int cmp_span_rev(const void *a,const void *b){return cmp_span(b,a);}
static bool num_arg(const char *s,unsigned max,unsigned *v){
    const size_t z=strlen(s);unsigned r=0;
    if(!z||z>5||strspn(s,"0123456789")!=z)return false;
    for(size_t i=0;i<z;i++)r=r*10u+(unsigned)(s[i]-'0');
    if(!r||r>max)return false;
    *v=r;return true;
}
/* Returns 0 ok, 1 usage error (message written to dst). */
static int run_filter(char **v,int n,const capbuf *in,capbuf *dst){
    static span L[MAX_LINES];
    const size_t cnt=lines_of(in,L,MAX_LINES);
    const char *f=v[0];
    if(eq(f,"grep")){
        bool icase=false,inv=false,count=false;int i=1;
        while(i<n && v[i][0]=='-' && v[i][1]){
            for(const char *q=v[i]+1;*q;q++){
                if(*q=='i')icase=true;else if(*q=='v')inv=true;else if(*q=='c')count=true;
                else{cap_put(dst,"ERR pipe grep: flags -i -v -c\n");return 1;}
            }
            i++;
        }
        if(n-i!=1){cap_put(dst,"ERR pipe usage: grep [-ivc] PATTERN\n");return 1;}
        unsigned hits=0;
        for(size_t k=0;k<cnt;k++){
            if(contains(L[k].p,L[k].n,v[i],icase)!=inv){
                hits++;
                if(!count)cap_span(dst,L[k].p,L[k].n);
            }
        }
        if(count){char t[24];snprintf(t,sizeof t,"%u\n",hits);cap_put(dst,t);}
        return 0;
    }
    if(eq(f,"head")||eq(f,"tail")){
        unsigned want=10;
        if(n==3 && eq(v[1],"-n")){if(!num_arg(v[2],MAX_LINES,&want)){cap_put(dst,"ERR pipe: -n 1..4096\n");return 1;}}
        else if(n!=1){cap_put(dst,"ERR pipe usage: head|tail [-n N]\n");return 1;}
        const bool head=eq(f,"head");
        const size_t from=head?0:(cnt>want?cnt-want:0);
        const size_t to=head?(cnt<want?cnt:want):cnt;
        for(size_t k=from;k<to;k++)cap_span(dst,L[k].p,L[k].n);
        return 0;
    }
    if(eq(f,"wc")){
        if(n>2 || (n==2 && !eq(v[1],"-l") && !eq(v[1],"-w") && !eq(v[1],"-c"))){
            cap_put(dst,"ERR pipe usage: wc [-l|-w|-c]\n");return 1;
        }
        size_t words=0;bool inw=false;
        for(size_t i=0;i<in->n;i++){
            const bool sp=in->b[i]==' '||in->b[i]=='\n'||in->b[i]=='\t';
            if(!sp&&!inw)words++;
            inw=!sp;
        }
        char t[64];
        if(n==1)snprintf(t,sizeof t,"%7u %7u %7u\n",(unsigned)cnt,(unsigned)words,(unsigned)in->n);
        else snprintf(t,sizeof t,"%u\n",eq(v[1],"-l")?(unsigned)cnt:eq(v[1],"-w")?(unsigned)words:(unsigned)in->n);
        cap_put(dst,t);return 0;
    }
    if(eq(f,"sort")){
        if(n>2 || (n==2 && !eq(v[1],"-r"))){cap_put(dst,"ERR pipe usage: sort [-r]\n");return 1;}
        qsort(L,cnt,sizeof *L,n==2?cmp_span_rev:cmp_span);
        for(size_t k=0;k<cnt;k++)cap_span(dst,L[k].p,L[k].n);
        return 0;
    }
    if(eq(f,"uniq")){
        if(n!=1){cap_put(dst,"ERR pipe usage: uniq\n");return 1;}
        for(size_t k=0;k<cnt;k++){
            if(k && L[k].n==L[k-1].n && !memcmp(L[k].p,L[k-1].p,L[k].n))continue;
            cap_span(dst,L[k].p,L[k].n);
        }
        return 0;
    }
    cap_put(dst,"ERR pipe: only grep head tail wc sort uniq may follow |\n");
    return 1;
}
static bool has_err_line(const capbuf *c){
    if(c->n>=4 && !memcmp(c->b,"ERR ",4))return true;
    for(size_t i=0;i+5<=c->n;i++)if(c->b[i]=='\n' && !memcmp(c->b+i+1,"ERR ",4))return true;
    return false;
}
static int run_compound(wb_shell_engine *s,const char *line,wb_out *out,const wb_shell_ops *ops){
    char buf[WB_SH_LINE+1];
    char *seg[MAX_SEGS];int conn[MAX_SEGS];int nseg=0;
    const size_t z=strlen(line);
    if(z>WB_SH_LINE)return say(out,"ERR command too long\n");
    memcpy(buf,line,z+1);
    /* Split on unquoted ';' and '&&'. A single '&' (background) is refused. */
    char q=0;seg[nseg]=buf;conn[nseg++]=0;
    for(size_t i=0;buf[i];i++){
        const char c=buf[i];
        if(q){if(c==q)q=0;continue;}
        if(c=='\''||c=='"'){q=c;continue;}
        if(c==';'||(c=='&'&&buf[i+1]=='&')){
            if(nseg==MAX_SEGS)return say(out,"ERR too many chained commands (max 8)\n");
            const int kind=c==';'?0:1;buf[i]=0;
            if(kind)buf[++i]=0;
            seg[nseg]=buf+i+1;conn[nseg++]=kind;
        }else if(c=='&')return say(out,"ERR syntax: background '&' is not supported\n");
    }
    if(q)return say(out,"ERR syntax: unterminated quote\n");
    capbuf A={malloc(CAP_BYTES),0,false},B={malloc(CAP_BYTES),0,false};
    if(!A.b||!B.b){free(A.b);free(B.b);return say(out,"ERR nomem\n");}
    int rc=0;bool prev_ok=true;
    for(int k=0;k<nseg && rc==0;k++){
        if(conn[k]==1 && !prev_ok)continue;
        char *st[MAX_STAGES];int ns=0;q=0;st[ns++]=seg[k];
        bool too_many=false;
        for(char *p=seg[k];*p;p++){
            if(q){if(*p==q)q=0;continue;}
            if(*p=='\''||*p=='"'){q=*p;continue;}
            if(*p=='|'){
                if(ns==MAX_STAGES){too_many=true;break;}
                *p=0;st[ns++]=p+1;
            }
        }
        if(too_many){rc=say(out,"ERR too many pipe stages (max 6)\n");break;}
        const char *first=st[0];while(*first==' '||*first=='\t')first++;
        if(!*first){
            if(ns>1||conn[k]==1){rc=say(out,"ERR syntax: empty command\n");break;}
            continue; /* tolerate "cmd ;" */
        }
        const bool needs_capture=ns>1 || (k+1<nseg && conn[k+1]==1);
        if(!needs_capture){rc=wb_shell_run_one(s,st[0],out,ops);prev_ok=true;continue;}
        A.n=0;A.over=false;
        wb_out cap={&A,cap_write};
        rc=wb_shell_run_one(s,st[0],&cap,ops);
        if(rc<0)break;
        bool ok=!has_err_line(&A);
        for(int j=1;j<ns;j++){
            char wbuf[WB_SH_LINE+1],*v[NWORDS];const int n=split(st[j],wbuf,v);
            B.n=0;B.over=false;
            if(n<1){cap_put(&B,"ERR syntax: empty pipe stage\n");ok=false;}
            else if(run_filter(v,n,&A,&B))ok=false;
            capbuf t=A;A=B;B=t;
        }
        if(A.n && out->write(out->ctx,A.b,A.n)<0){rc=-1;break;}
        if(A.over && say(out,"\nERR pipe buffer limit (64 KiB); output truncated\n")<0){rc=-1;break;}
        prev_ok=ok;
    }
    free(A.b);free(B.b);
    return rc;
}
#endif
int wb_shell_run(wb_shell_engine *s,const char *line,wb_out *out,const wb_shell_ops *ops){
#ifdef WB_SHELL2
    if(s&&line&&out&&out->write&&ops){
        size_t z=0;while(z<=WB_SH_LINE && line[z])z++;
        if(z<=WB_SH_LINE && has_operator(line))return run_compound(s,line,out,ops);
    }
#endif
    return wb_shell_run_one(s,line,out,ops);
}
