#include "wb_shell_vfs.h"
#include "wb_game_logs_path.h"
#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __vita__
enum { PATH_CAP=128, NAME_CAP=100, DEPTH_LIMIT=12, SCAN_LIMIT=4096,
       LIST_BYTES=28672, CAT_BYTES=4096 };
#else
enum { PATH_CAP=128, NAME_CAP=100, DEPTH_LIMIT=12, SCAN_LIMIT=512,
       LIST_BYTES=8192, CAT_BYTES=4096 };
#endif
enum area { BLOCKED, MOUNT_ROOT, INCOMING, DATA_ROOT, DIAG_DIR, DIAG_FILE, GAME_PARENT, GAME_LOGS, GENERAL };
/* WB_SHELL2 (Workbench 2.0 production build): read-only projection of every
 * ux0:/, ur0:/ and uma0:/ entry, except Workbench's private data directory
 * (only the public diag files stay visible there). Writes are unchanged. */
static size_t mount_len(const char *p){
    if(!strncmp(p,"ux0:/",5))return 5;
#ifdef WB_SHELL2
    if(!strncmp(p,"ur0:/",5))return 5;
    if(!strncmp(p,"uma0:/",6))return 6;
#endif
    return 0;
}
static const char *const ERR_DENIED="ERR access denied\n";
static const char *const ERR_IO="ERR filesystem I/O\n";
static const char *const ERR_LIMIT="ERR directory limit; use a narrower path\n";

/* No dotfiles, FAT aliases, control codes or terminal metacharacters in
 * printed names. Names with spaces are supported through shell quoting. */
static int name_ok(const char *s,size_t n){
    if(!n||n>NAME_CAP||s[0]=='.'||s[0]==' '||s[n-1]==' '||s[n-1]=='.')return 0;
    for(size_t i=0;i<n;i++){
        unsigned c=(unsigned char)s[i];
        if(!(c>='a'&&c<='z')&&!(c>='A'&&c<='Z')&&!(c>='0'&&c<='9')&&
           !strchr(" ._()-",c))return 0;
    }
    return 1;
}
static int diag_name(const char *n){
    return !strcmp(n,"run.log")||!strcmp(n,"startup.log")||
           !strcmp(n,"install.log")||!strcmp(n,"timeline.txt");
}
static enum area policy(const char *p){
    const size_t m=p?mount_len(p):0;
    if(!m||strlen(p)>=PATH_CAP)return BLOCKED;
    if(!p[m])return MOUNT_ROOT;
    const char *s=p+m;unsigned depth=0;
    for(;;){
        const char *end=strchr(s,'/');size_t n=end?(size_t)(end-s):strlen(s);
        if(++depth>DEPTH_LIMIT||!name_ok(s,n))return BLOCKED;
        if(!end)break;
        s=end+1;
    }
    if(!strcmp(p,"ux0:/VITA-POC")||!strncmp(p,"ux0:/VITA-POC/",14))return INCOMING;
    if(!strcmp(p,"ux0:/data"))return DATA_ROOT;
    if(wb_game_data_parent(p))return GAME_PARENT;
    if(wb_game_logs_path(p))return GAME_LOGS;
    if(!strcmp(p,"ux0:/data/INAP00018"))return DIAG_DIR;
    const char root[]="ux0:/data/INAP00018/";
    if(!strncmp(p,root,sizeof root-1)&&diag_name(p+sizeof root-1))return DIAG_FILE;
#ifdef WB_SHELL2
    if(!strncmp(p,"ux0:/data/INAP00018",19))return BLOCKED; /* private identity */
    return GENERAL;
#else
    return BLOCKED;
#endif
}
static int is_regular(const SceIoStat *st){
    return SCE_S_ISREG(st->st_mode)&&st->st_size>=0;
}
static int typed(enum area a,const SceIoStat *st,const char *p){
    if(a==BLOCKED)return 0;
    if(a==DIAG_FILE)return is_regular(st);
    if(a==GENERAL)return is_regular(st)||SCE_S_ISDIR(st->st_mode);
    if(a==GAME_LOGS&&!wb_game_logs_exact(p))return is_regular(st)||SCE_S_ISDIR(st->st_mode);
    if(a==INCOMING&&strcmp(p,"ux0:/VITA-POC"))return is_regular(st)||SCE_S_ISDIR(st->st_mode);
    return !!SCE_S_ISDIR(st->st_mode);
}
/* st_mode comes from an exact matching entry in its parent, not a stat
 * which could silently resolve a symlink or a filesystem case alias. */
static const char *lookup(const char *p,enum area a,SceIoStat *st){
    if(a==BLOCKED)return ERR_DENIED;
    if(a==MOUNT_ROOT)return NULL; /* trusted platform mount */
    const size_t m=mount_len(p);
    char parent[PATH_CAP];size_t used=m;memcpy(parent,p,m);parent[m]=0;
    const char *s=p+m;unsigned budget=SCAN_LIMIT;
    while(*s){
        const char *slash=strchr(s,'/');size_t len=slash?(size_t)(slash-s):strlen(s);
        int fd=sceIoDopen(parent);if(fd<0)return ERR_IO;
        const char *error=ERR_LIMIT;
        while(budget){
            --budget;SceIoDirent entry={0};
            int n=sceIoDread(fd,&entry);
            if(n<0){error=ERR_IO;break;}
            if(!n){error="ERR not found\n";break;}
            const char *end=memchr(entry.d_name,0,sizeof entry.d_name);
            if(!end){error=ERR_IO;break;}
            if((size_t)(end-entry.d_name)==len&&!memcmp(s,entry.d_name,len)){
                *st=entry.d_stat;
                error=slash?(!SCE_S_ISDIR(st->st_mode)?ERR_DENIED:NULL):
                            (!typed(a,st,p)?ERR_DENIED:NULL);
                break;
            }
        }
        if(sceIoDclose(fd)<0)return ERR_IO;
        if(error||!slash)return error;
        if(used>m)parent[used++]='/';
        memcpy(parent+used,s,len);parent[used+=len]=0;s=slash+1;
    }
    return ERR_IO;
}
static int err(wb_out *o,const char *why){
    return wb_out_puts(o,why)==0?1:-1;
}
int wb_vita_shell_open_game_log(const char *p,int *fd){
    if(!fd)return -1;
    *fd=-1;
    const enum area a=policy(p);SceIoStat st={0};
    if(a!=GAME_LOGS||lookup(p,a,&st)||!is_regular(&st))return -1;
    const int opened=sceIoOpen(p,SCE_O_RDONLY,0);
    if(opened<0)return -1;
    *fd=opened;return 0;
}
int wb_vita_shell_isdir(void *ctx,const char *p,wb_out *out){
    (void)ctx;enum area a=policy(p);SceIoStat st={0};const char *e=lookup(p,a,&st);
    if(e)return err(out,e);
    return a==MOUNT_ROOT||SCE_S_ISDIR(st.st_mode)?0:err(out,"ERR not a directory\n");
}
/* Dates are local filesystem fields, not guessed UTC timestamps. Unknown
 * timestamp = '?'. Permission bits describe native metadata, not shell grants. */
static int line(char *buf,size_t cap,const char *name,const SceIoStat *st,bool detailed){
    int dir=!!SCE_S_ISDIR(st->st_mode);
    if(!detailed)return snprintf(buf,cap,"%s%s\n",name,dir?"/":"");
    char mode[]="----------",date[32]="?",size[32]="-";mode[0]=dir?'d':'-';
    for(unsigned i=0;i<9;i++)if(st->st_mode&(1u<<(8-i)))mode[i+1]="rwx"[i%3];
    unsigned y=st->st_mtime.year,m=st->st_mtime.month,d=st->st_mtime.day;
    unsigned h=st->st_mtime.hour,min=st->st_mtime.minute;
    if(y>=1980&&y<=9999&&m>=1&&m<=12&&d>=1&&d<=31&&h<=23&&min<=59)
        (void)snprintf(date,sizeof date,"%04u-%02u-%02u %02u:%02u",y,m,d,h,min);
    if(!dir)(void)snprintf(size,sizeof size,"%" PRIu64,(uint64_t)st->st_size);
    return snprintf(buf,cap,"%s %12s %-16s %s%s\n",mode,size,date,name,dir?"/":"");
}
int wb_vita_shell_list(void *ctx,const char *p,bool detailed,wb_out *out){
    (void)ctx;enum area a=policy(p);SceIoStat st={0};const char *e=lookup(p,a,&st);
    if(e)return err(out,e);
    if(a!=MOUNT_ROOT&&!SCE_S_ISDIR(st.st_mode)){
        char row[256];const char *leaf=strrchr(p,'/')+1;int n=line(row,sizeof row,leaf,&st,detailed);
        if(n<0||(size_t)n>=sizeof row)return err(out,ERR_IO);
        return out->write(out->ctx,row,(size_t)n)==0?0:-1;
    }
    int fd=sceIoDopen(p);if(fd<0)return err(out,ERR_IO);
    char *result=malloc(LIST_BYTES+1);size_t used=0;
    if(!result)e="ERR nomem\n";
    unsigned count=0;
    while(!e){
        if(++count>SCAN_LIMIT){e=ERR_LIMIT;break;}
        SceIoDirent entry={0};int n=sceIoDread(fd,&entry);
        if(n<0){e=ERR_IO;break;}if(!n)break;
        const char *end=memchr(entry.d_name,0,sizeof entry.d_name);
        if(!end){e=ERR_IO;break;}
        if(!name_ok(entry.d_name,(size_t)(end-entry.d_name)))continue;
        char child[PATH_CAP];
        int z=snprintf(child,sizeof child,"%s%s%s",p,a==MOUNT_ROOT?"":"/",entry.d_name);
        if(z<0||(size_t)z>=sizeof child||!typed(policy(child),&entry.d_stat,child))continue;
        int l=line(result+used,LIST_BYTES+1-used,entry.d_name,&entry.d_stat,detailed);
        if(l<0||(size_t)l>LIST_BYTES-used){e=ERR_LIMIT;break;}
        used+=(size_t)l;
    }
    if(sceIoDclose(fd)<0)e=ERR_IO;
    /* A late I/O or capacity error must not look like a full, empty or
     * silently truncated directory. Emit list only after clean EOF. */
    int rc=e?err(out,e):(!used||out->write(out->ctx,result,used)==0?0:-1);
    free(result);return rc;
}
/* Validate the entire file before emitting any bytes. Refuse ANSI/C0/C1,
 * bidi/format controls, invalid UTF-8 or bare CR. Allow CRLF and tab only as
 * structural input, output normalized LF and space. Never dump raw binary. */
static int plain(uint8_t *b,size_t n,size_t *written){
    size_t i=0,o=0;
    while(i<n){
        size_t start=i;uint32_t c=b[i++];
        if(c=='\r'){if(i==n||b[i]!='\n')return 0;continue;}
        if(c=='\n'||c=='\t'){b[o++]=c=='\t'?' ':'\n';continue;}
        if(c<32||c==127)return 0;
        unsigned take;uint32_t val,min;
        if(c<128){b[o++]=(uint8_t)c;continue;}
        if(c>=194&&c<=223){take=1;val=c&31u;min=128;}
        else if(c>=224&&c<=239){take=2;val=c&15u;min=2048;}
        else if(c>=240&&c<=244){take=3;val=c&7u;min=65536;}
        else return 0;
        if(n-i<take)return 0;
        while(take--){if((b[i]&192u)!=128u)return 0;val=val*64u+(b[i++]&63u);}
        if(val<min||val<160||val>0x10ffff||(val>=0xd800&&val<=0xdfff)||
            val==0x061c||val==0x00ad||(val>=0x200b&&val<=0x200f)||
            (val>=0x2028&&val<=0x202e)||(val>=0x2060&&val<=0x206f)||
            val==0xfeff||(val>=0xe0000&&val<=0xe007f))return 0;
        memmove(b+o,b+start,i-start);o+=i-start;
    }
    *written=o;return 1;
}
int wb_vita_shell_cat(void *ctx,const char *p,wb_out *out){
    (void)ctx;enum area a=policy(p);SceIoStat st={0};const char *e=lookup(p,a,&st);
    if(e)return err(out,e);
    if(a==MOUNT_ROOT||!is_regular(&st))return err(out,"ERR not a regular file\n");
    if(st.st_size>CAT_BYTES)return err(out,"ERR cat limit (4096 bytes); use file transfer\n");
    int fd=sceIoOpen(p,SCE_O_RDONLY,0);if(fd<0)return err(out,ERR_IO);
    size_t total=(size_t)st.st_size,done=0,norm=0;
    uint8_t *b=malloc(total+1);
    if(!b)e="ERR nomem\n";
    while(!e&&done<total){
        int n=sceIoRead(fd,b+done,(SceSize)(total-done));
        if(n<=0||(size_t)n>total-done){e=ERR_IO;break;}
        done+=(size_t)n;
    }
    if(!e&&sceIoRead(fd,b+done,1)!=0)e=ERR_IO;
    if(sceIoClose(fd)<0)e=ERR_IO;
    if(!e&&!plain(b,total,&norm))e="ERR cat requires safe UTF-8 text; use file transfer\n";
    if(!e&&norm&&b[norm-1]!='\n')b[norm++]='\n';
    int rc=e?err(out,e):(!norm||out->write(out->ctx,(const char*)b,norm)==0?0:-1);
    free(b);return rc;
}
