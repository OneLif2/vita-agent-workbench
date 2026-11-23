#ifndef WB_CRASH_INDEX_H
#define WB_CRASH_INDEX_H
/* Fixed, nonrecursive, paired-PTY-only metadata query. No file-open import;
 * timestamps are the device filesystem's civil fields, not presumed UTC. Do
 * not infer the crashing title from a generic eboot.bin filename. */
#include "wb_cmd.h"
#include "wb_out.h"
#include "wb_crash_limit.h"
#include <psp2/io/dirent.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { char name[128],date[20]; uint64_t bytes; } wbcr_row;

static int wbcr_alnum(unsigned char c) {
    return (c>='0'&&c<='9')||(c>='a'&&c<='z')||(c>='A'&&c<='Z');
}
static size_t wbcr_name(const char *p,size_t cap) {
    const char prefix[]="psp2core-";
    const char *end=memchr(p,0,cap);
    if(!end)return 0;
    size_t n=(size_t)(end-p),k=sizeof prefix-1;
    if(n<=k||n>=sizeof(((wbcr_row*)0)->name)||memcmp(p,prefix,k)||
       !wbcr_alnum((unsigned char)p[k])||!wbcr_alnum((unsigned char)p[n-1]))return 0;
    for(size_t i=k;i<n;++i){
        unsigned char c=(unsigned char)p[i];
        if(!wbcr_alnum(c)&&c!='_'&&c!='-'&&c!='.')return 0;
        if(c=='.'&&p[i-1]=='.')return 0;
    }
    return n;
}
static void wbcr_date(char out[20],const SceIoStat *s) {
    const unsigned days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    unsigned y=s->st_mtime.year,m=s->st_mtime.month,d=s->st_mtime.day,
             h=s->st_mtime.hour,minute=s->st_mtime.minute,sec=s->st_mtime.second;
    out[0]=0;
    if(y<1980||y>9999||!m||m>12||!d||h>23||minute>59||sec>59)return;
    unsigned max=days[m-1]+(m==2&&y%4==0&&(y%100!=0||y%400==0));
    if(d>31||d>max)return;
    (void)snprintf(out,20,"%04u-%02u-%02uT%02u:%02u:%02u",y,m,d,h,minute,sec);
}
/* Known ISO dates descend; the empty (unknown) key sorts after every known
 * date. Ties sort by literal ASCII filename, independent of Dread order. */
static int wbcr_before(const wbcr_row *a,const wbcr_row *b) {
    int t=strcmp(a->date,b->date);
    return t?t>0:strcmp(a->name,b->name)<0;
}
static int wb_crash_index(const wb_cmd *c,int owner_pty,wb_out *out,int *status) {
    *status=1;
    if(!owner_pty)return wb_out_puts(out,"ERR crash-index no-pty\n");
    unsigned limit=c->argc==0?WB_CRASH_DEFAULT:c->argc==1?wb_crash_limit(c->argv[0]):0;
    if(!limit)return wb_out_puts(out,"ERR crash-index usage\n");
    wbcr_row *top=calloc(limit,sizeof *top);
    if(!top)return wb_out_puts(out,"ERR crash-index nomem\n");
    int fd=sceIoDopen("ux0:data");
    if(fd<0){free(top);return wb_out_puts(out,"ERR crash-index open\n");}
    unsigned scanned=0,matched=0,shown=0;
    const char *err=NULL;
    for(;;){
        SceIoDirent e={0};
        int rc=sceIoDread(fd,&e);
        if(rc==0)break;
        if(rc<0){err="read";break;}
        if(++scanned>WB_CRASH_SCAN_MAX){err="scan-limit";break;}
        if(!SCE_S_ISREG(e.d_stat.st_mode))continue;
        size_t n=wbcr_name(e.d_name,sizeof e.d_name);
        if(!n)continue;
        wbcr_row r={0};
        r.bytes=(uint64_t)e.d_stat.st_size;
        if(r.bytes>(uint64_t)INT64_MAX){err="metadata";break;}
        memcpy(r.name,e.d_name,n+1);wbcr_date(r.date,&e.d_stat);++matched;
        unsigned i=0;while(i<shown&&!wbcr_before(&r,top+i))++i;
        if(i<limit){
            if(shown<limit)++shown;
            memmove(top+i+1,top+i,(shown-i-1)*sizeof *top);top[i]=r;
        }
    }
    if(sceIoDclose(fd)<0&&!err)err="close";
    if(err){free(top);return wb_out_printf(out,"ERR crash-index %s\n",err);}
    /* Never emit a partial directory result as a successful scan. A delivery
     * interrupted during streaming lacks the full row count and END receipt. */
    int rc=wb_out_printf(out,"OK crash-index matched=%u shown=%u truncated=%u clock=device-local\n",
                         matched,shown,(unsigned)(matched>shown));
    for(unsigned i=0;rc>=0&&i<shown;++i)
        rc=wb_out_printf(out,"crash name=%s modified=%s bytes=%" PRIu64 "\n",top[i].name,
                         top[i].date[0]?top[i].date:"unknown",top[i].bytes);
    free(top);
    if(rc<0)return rc;
    rc=wb_out_puts(out,"END crash-index\n");if(rc>=0)*status=0;
    return rc;
}
#endif
