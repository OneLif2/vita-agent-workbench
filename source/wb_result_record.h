#ifndef WB_RESULT_RECORD_H
#define WB_RESULT_RECORD_H
#include "wb_app_registry.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A completed job is not the same as a successful launch. Parse only the six
 * known ASCII fields of this registered TestApp and validate its assertions. */
static inline int wb_rr_num(const char **p,int64_t *out){
    const char *s=*p;int neg=*s=='-';if(neg)++s;
    unsigned n=0;int64_t value=0;
    while(*s>='0'&&*s<='9'){if(++n>10)return 0;value=value*10+(*s++-'0');}
    if(!n)return 0;
    *out=neg?-value:value;*p=s;return 1;
}
static inline int wb_rr_lit(const char **p,const char *v){
    size_t n=strlen(v);if(strncmp(*p,v,n))return 0;*p+=n;return 1;
}
static inline int wb_rr_assert(const char *type,const char *p){
    int64_t a=0,b=0;
    if(!strcmp(type,"fs-smoke")){
        if(!strcmp(p,"open-write-failed"))return 0;
        const char *orig=p;
        if(!wb_rr_lit(&p,"write=")||!wb_rr_num(&p,&a)||!wb_rr_lit(&p," read=")||
           !wb_rr_num(&p,&b)||!wb_rr_lit(&p," match=")||strlen(p)!=1||(*p!='0'&&*p!='1'))return -1;
        return !strcmp(orig,"write=64 read=64 match=1");
    }
    if(!strcmp(type,"compute-smoke")){
        const char *orig=p;
        if(!wb_rr_lit(&p,"fnv1a=0x")||strspn(p,"0123456789ABCDEF")!=8)return -1;
        p+=8;
        if(!wb_rr_lit(&p," expected=0x")||strlen(p)!=8||strspn(p,"0123456789ABCDEF")!=8)return -1;
        return !strcmp(orig,"fnv1a=0x655C5FFD expected=0x655C5FFD");
    }
    if(!strcmp(type,"power-smoke")){
        if(!wb_rr_lit(&p,"battery=")||!wb_rr_num(&p,&a)||!wb_rr_lit(&p," temp_raw=")||
           !wb_rr_num(&p,&b)||*p)return -1;
        return a>=0&&a<=100&&b>-2000&&b<9000;
    }
    return -1;
}
/* -1 inconclusive, 0 case failed, 1 case passed. Input is not trusted text. */
static inline int wb_rr_check(char *p,size_t n,const char *title,const char *cse,const char *job,const char **assertion){
    if(!n||n>1024||memchr(p,0,n))return -1;
    size_t w=0;
    for(size_t i=0;i<n;i++){
        unsigned b=(unsigned char)p[i];
        if(b=='\r'){if(i+1>=n||p[i+1]!='\n')return -1;continue;}
        if(b!='\n'&&(b<32||b>126))return -1;
        p[w++]=(char)b;
    }
    p[w]=0;
    static const char *const keys[]={"job","title","case","build","assert","result"};
    const char *f[6]={0};
    while(*p){char *next=strchr(p,'\n');if(next)*next=0;char *eq=strchr(p,'=');
        if(!eq||!eq[1])return -1;
        *eq++=0;
        unsigned j=0;while(j<6&&strcmp(p,keys[j]))++j;
        if(j==6||f[j])return -1;
        f[j]=eq;
        if(!next)break;
        p=next+1;
    }
    for(unsigned j=0;j<6;j++)if(!f[j])return -1;
    if(strcmp(f[0],job)||strcmp(f[1],title)||strcmp(f[2],cse))return -1;
    int approved=0;
    for(size_t j=0;j<WB_REG_ROWS;j++){
        char build[48];const wb_reg_entry *r=&wb_reg_entries[j];
        if(strcmp(title,r->title)||wb_reg_launch(title,r->version,cse)!=WB_REG_OK)continue;
        int len=snprintf(build,sizeof build,"%s-testapp",r->version);
        if(len>0&&(size_t)len<sizeof build&&!strcmp(build,f[3]))approved=1;
    }
    int val=wb_rr_assert(cse,f[4]);
    if(!approved||val<0||strcmp(f[5],val?"PASS":"FAIL"))return -1;
    *assertion=f[4];return val;
}
#endif
