/* Exercise the exact native adapter. Simulated Vita filesystem + AppMgr + promoter
 * implement only their own contracts; path verification, filesystem enumeration,
 * SHA, member logic, shape/SFO/head checks all run production code. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_ver.h"
#include "wb_err.h"
#include "wb_out.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_head.h"
#include "wb_app_patch_recipe.h"
#include "fixture_data.inc"
enum { DIR=1, REG=2, LINK=3,SCE_O_RDONLY=1,SCE_O_WRONLY=2,SCE_O_CREAT=4 };
typedef int SceUID;
typedef struct {int st_mode,st_size;} SceIoStat;
typedef struct {char d_name[256];SceIoStat d_stat;} SceIoDirent;
#define SCE_S_ISREG(x) ((x)==REG)
#define SCE_S_ISDIR(x) ((x)==DIR)
#define ROOT_I "ux0:/app/" WB_PATCH_TITLE
#define ST "ux0:/data/INAP00018/patch-0213"
#define INPUT WB_INCOMING "/patch-unique.bin"
typedef struct {char p[200];int kind,n; unsigned char data[2100];} node;
static node f[100];static int files=1;
static struct handle{int id,pos,used,dir;} fd[20];
static int writes,creates,promotes,globals,opened; static const char *mode;static char result[1024];
static void norm(char *dest,const char *src){
    size_t n=strlen(src);assert(n<=198);if(!strncmp(src,"ux0:data",8)){memcpy(dest,"ux0:/",5);memcpy(dest+5,src+4,n-3);}
    else memcpy(dest,src,n+1);
}
static int id(const char *p){char s[200];norm(s,p);for(int i=1;i<files;i++)if(!strcmp(f[i].p,s))return i;return 0;}
static int make(const char *p,int kind,const void *data,size_t n){
    assert(files<100&&n<=sizeof(f[0].data));int i=id(p);
    if(!i){i=files++;norm(f[i].p,p);}f[i].kind=kind;f[i].n=(int)n;if(n)memcpy(f[i].data,data,n);return i;
}
static int getfd(int i,int dir){for(int j=1;j<20;j++)if(!fd[j].used){fd[j]=(struct handle){i,0,1,dir};opened++;return j;}abort();}
static int sceIoGetstat(const char *p,SceIoStat *st){int i=id(p);if(!i)return (int)0x80010002u;*st=(SceIoStat){f[i].kind,f[i].n};return 0;}
static int sceIoDopen(const char *p){int i=id(p);return i&&f[i].kind==DIR?getfd(i,1):-9;}
static int sceIoDread(int d,SceIoDirent *e){
    struct handle *h=fd+d;assert(h->used&&h->dir);
    const char *p=f[h->id].p;
    if(!strcmp(mode,"readdir-fail")&&!strcmp(p,ROOT_I "/sce_sys"))return -8;
    while(++h->pos<files){node *c=&f[h->pos];size_t n=strlen(p);const char *name=NULL;
        if(!strncmp(p,c->p,n)){
            if(!strcmp(p,"ux0:/"))name=c->p+n;
            else if(c->p[n]=='/')name=c->p+n+1;
        }
        if(name&&*name&&!strchr(name,'/')){
            snprintf(e->d_name,sizeof e->d_name,"%s",name);e->d_stat=(SceIoStat){c->kind,c->n};return 1;
        }
    }return 0;
}
static int sceIoDclose(int d){assert(fd[d].used&&fd[d].dir);fd[d].used=0;opened--;return 0;}
static int sceIoMkdir(const char *p,int perms){
    char canon[200];norm(canon,p);assert(!strncmp(canon,ST,sizeof(ST)-1)&&perms==0777);
    if(id(canon))return -17;
    creates++;make(canon,DIR,NULL,0);return 0;
}
static int sceIoOpen(const char *p,int flags,int perms){
    int i=id(p);char canon[200];norm(canon,p);
    if(flags!=SCE_O_RDONLY){assert(flags==(SCE_O_WRONLY|SCE_O_CREAT)&&perms==0666);assert(!strncmp(canon,ST "/",sizeof(ST)));
        assert(!i);i=make(canon,REG,NULL,0);creates++;
    }
    return i&&f[i].kind==REG?getfd(i,0):-9;
}
static int sceIoRead(int d,void *out,size_t n){
    struct handle *h=fd+d;assert(h->used&&!h->dir);node *v=&f[h->id];
    if(n>25)n=25;
    if((int)n>v->n-h->pos)n=(size_t)(v->n-h->pos);
    memcpy(out,v->data+h->pos,n);h->pos+=(int)n;return (int)n;
}
static int sceIoWrite(int d,const void *input,size_t n){
    struct handle *h=fd+d;assert(h->used&&!h->dir&&!strncmp(f[h->id].p,ST "/",sizeof(ST)));
    if(n>17)n=17;
    if(!strcmp(mode,"write-fail"))return 0;
    assert(h->pos+(int)n<=(int)sizeof f[0].data);memcpy(f[h->id].data+h->pos,input,n);h->pos+=(int)n;f[h->id].n=h->pos;writes++;return (int)n;
}
static int sceIoSyncByFd(int d,int flag){assert(fd[d].used&&flag==0);return !strcmp(mode,"sync-fail")?-5:0;}
static int sceIoClose(int d){
    struct handle *h=fd+d;assert(h->used&&!h->dir);node *v=&f[h->id];h->used=0;opened--;
    if(!strcmp(v->p,ST "/sce_sys/package/head.bin")&&id(ST "/media.rja")){
        if(!strcmp(mode,"stage-corrupt"))f[id(ST "/media.rja")].data[0]^=5;
        if(!strcmp(mode,"base-mutates"))f[id(ROOT_I "/strings.dat")].data[0]^=5;
        if(!strcmp(mode,"extra-stage"))make(ST "/foreign.dat",REG,"x",1);
    }
    return 0;
}
static int sceAppMgrGetIdByName(int *pid,const char *title){
    assert(!strcmp(title,WB_PATCH_TITLE));
    if(!strcmp(mode,"running")||(!strcmp(mode,"started-before-promote")&&id(ST "/sce_sys/package/head.bin"))){*pid=12;return 0;}
    if(!strcmp(mode,"unknown-pid"))return -5;
    *pid=-1;return (int)0x80802012u;
}
static int gate(void){assert(++globals==1);return strcmp(mode,"lost-gate");}
#define WB_PATCH_READY_OK() (strcmp(mode,"unsigned-session")!=0)
#define WB_PATCH_COMMIT_OK() gate()
#define WB_APP_BUDGET(sz,out) ((void)(sz),(void)(out),strcmp(mode,"no-space")?WB_OK:WB_E_LIMIT)
static struct{wb_out *out;uint64_t last,bytes,total;} wb_app_progress;
static uint64_t now_ms(void){return 10;}
static void wb_app_phase(const char *p,uint64_t total){(void)p;wb_app_progress.total=total;wb_app_progress.bytes=0;}
static int wb_app_count_progress(size_t n){wb_app_progress.bytes+=n;assert(wb_app_progress.bytes<=wb_app_progress.total);return !strcmp(mode,"cancel-progress")?WB_E_IO:WB_OK;}
static int wb_vita_promote_stage(const char *p,bool skip,int *detail){
    assert(id(p)==id(ST)&&skip&&promotes++==0);*detail=0;
    if(!strcmp(mode,"promote-fail"))return -99;
    for(unsigned j=0;j<WB_PATCH_FILE_COUNT;j++){
        char dst[200],from[200];snprintf(from,sizeof from,ST "/%s",wb_patch_target[j].path);
        snprintf(dst,sizeof dst,ROOT_I "/%s",wb_patch_target[j].path);
        node *s=&f[id(from)];assert(s->kind==REG&&id(dst));make(dst,REG,s->data,s->n);
    }
    if(!strcmp(mode,"post-corrupt"))f[id(ROOT_I "/build-manifest.json")].data[0]^=1;
    return WB_OK;
}
#include "wb_app_patch_vita.inc"
static int output(void *ctx,const char *b,size_t n){(void)ctx;size_t k=strlen(result);assert(k+n<sizeof result);memcpy(result+k,b,n);result[k+n]=0;return 0;}
int main(int argc,char **argv){
    assert(argc==2);mode=argv[1];unsigned base=!strcmp(mode,"apply-0109")?0:1;
    make("ux0:/",DIR,NULL,0);make("ux0:/app",DIR,NULL,0);make("ux0:/data",DIR,NULL,0);make(WB_ROOT,DIR,NULL,0);make(WB_INCOMING,DIR,NULL,0);make(ROOT_I,DIR,NULL,0);
    for(unsigned j=1;j<PA_NDIR;j++){
        char p[PA_PATH];pa_join(p,ROOT_I,pa_dirs[j]);make(p,DIR,NULL,0);
    }
    for(unsigned j=0;j<WB_PATCH_FILE_COUNT;j++){
        const wb_patch_file *r=&wb_patch_bases[base][j];char p[PA_PATH];pa_join(p,ROOT_I,r->path);
        make(p,REG,base_bytes[base][j],r->bytes);
    }
    make(INPUT,REG,new_boot,wb_patch_target[0].bytes);
    if(!strcmp(mode,"head-allowed")||!strcmp(mode,"bad-head")){
        unsigned char b[WB_HEAD_SIZE];assert(wb_head_build(b,sizeof b,WB_PATCH_TITLE,NULL)==0);
        if(!strcmp(mode,"bad-head"))b[12]^=1;
        make(ROOT_I "/" PA_HEAD,REG,b,sizeof b);
    }
    if(!strcmp(mode,"work-allowed")||!strcmp(mode,"bad-work")){
        unsigned char w[513]={0};
        make(ROOT_I "/" PA_WORK,REG,w,!strcmp(mode,"bad-work")?513:512);
    }
    if(!strcmp(mode,"foreign-file"))make(ROOT_I "/extra.bin",REG,"x",1);
    if(!strcmp(mode,"foreign-dir"))make(ROOT_I "/other",DIR,NULL,0);
    if(!strcmp(mode,"base-sha"))f[id(ROOT_I "/strings.dat")].data[0]^=6;
    if(!strcmp(mode,"base-version"))memcpy(f[id(ROOT_I "/sce_sys/param.sfo")].data+version_offset,"01.88",5);
    if(!strcmp(mode,"wrong-title"))memcpy(f[id(ROOT_I "/sce_sys/param.sfo")].data+title_offset,"RJGP52237",9);
    if(!strcmp(mode,"already-target"))memcpy(f[id(ROOT_I "/sce_sys/param.sfo")].data+version_offset,"01.12",5);
    if(!strcmp(mode,"input-corrupt"))f[id(INPUT)].data[0]^=42;
    if(!strcmp(mode,"wrong-size"))f[id(INPUT)].n--;
    if(!strcmp(mode,"link-input"))f[id(INPUT)].kind=LINK;
    if(!strcmp(mode,"link-base"))f[id(ROOT_I "/sce_sys/livearea")].kind=LINK;
    if(!strcmp(mode,"stale"))make(ST,DIR,NULL,0);
    int missing=id(ROOT_I "/strings.dat");if(!strcmp(mode,"missing"))f[missing].p[0]=0;
    const bool apply=strcmp(mode,"plan")!=0;
    const char *input=!strcmp(mode,"path")?"ux0:/VITA-POC/../app/RJGM52237/eboot.bin":INPUT;
    wb_out sink={NULL,output};
    int rc=wb_app_patch_execute(input,apply,&sink);
    assert(opened==0);
    int ok=!strcmp(mode,"apply-0109")||!strcmp(mode,"apply-0110")||!strcmp(mode,"head-allowed")||!strcmp(mode,"work-allowed")||!apply;
    assert((rc==WB_OK)==ok);
    int uncertain=!strcmp(mode,"promote-fail")||!strcmp(mode,"post-corrupt");
    assert(promotes==((ok&&apply)||uncertain));assert(globals==((ok&&apply)||uncertain||!strcmp(mode,"lost-gate")));
    if(!apply||!strcmp(mode,"base-sha")||!strcmp(mode,"input-corrupt")||!strcmp(mode,"wrong-title")||
       !strcmp(mode,"foreign-file")||!strcmp(mode,"stale")||!strcmp(mode,"running")||!strcmp(mode,"unsigned-session"))assert(!writes&&!creates);
    assert((strstr(result,"OK app-patch")!=NULL)==ok);
    printf("%s: writes=%d promotions=%d %s",mode,writes,promotes,result);
    return 0;
}
