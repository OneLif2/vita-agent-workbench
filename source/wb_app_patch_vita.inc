/* Included only in the paired terminal core. No shell path from the request
 * is EVER used as a destination. The only update operation on the game title
 * is a single platform promotion of a verified, private, complete tree. */
#include "wb_app_patch_recipe.h"
#ifndef WB_PATCH_BASE_SFO_AT
#define WB_PATCH_BASE_SFO_AT(i) (wb_patch_base_versions[i])
#endif
#ifndef WB_PATCH_COMMIT_OK
#error Gate the final promotion against the authenticated owner session
#endif
#define PA_STAGE WB_ROOT "/patch-0213"
#define PA_INST "ux0:/app/" WB_PATCH_TITLE
#define PA_HEAD "sce_sys/package/head.bin"
#define PA_WORK "sce_sys/package/work.bin"
#define PA_ENOENT UINT32_C(0x80010002)
enum { PA_BUF=262144, PA_PATH=224, PA_SFO=4096, PA_WORK_SIZE=512 };
typedef struct { unsigned char *buf; const char *why; int raw; } pa_io;
static const char *const pa_dirs[]={"","sce_sys","sce_sys/livearea","sce_sys/livearea/contents","sce_sys/package"};
#define PA_NDIR (sizeof(pa_dirs)/sizeof(pa_dirs[0]))
_Static_assert(WB_PATCH_FILE_COUNT+PA_NDIR<31,"shape masks fit");
static int pa_bad(pa_io *s,const char *why,int raw){
    if(!s->why){s->why=why;s->raw=raw;}return WB_E_STATE;
}
static int pa_join(char *out,const char *root,const char *rel){
    int n=snprintf(out,PA_PATH,"%s%s%s",root,*rel?"/":"",rel);return n>=0&&n<PA_PATH;
}
static bool pa_input_ok(const char *p){
    static const char root[]=WB_INCOMING "/";
    if(!p||strncmp(p,root,sizeof root-1))return false;
    const char *n=p+sizeof root-1;size_t z=strlen(n);
    if(z<=4||z>99||n[0]=='.'||strstr(n,"..")||strcmp(n+z-4,".bin"))return false;
    for(size_t i=0;i<z;i++){unsigned char c=(unsigned char)n[i];if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return false;}
    return true;
}
/* Exact parent entry (not getstat of a path that could resolve a link or case
 * alias). Device-created directories and incoming are bounded separately. */
static int pa_child(pa_io *s,const char *parent,const char *name,bool dir){
    int d=sceIoDopen(parent);if(d<0)return pa_bad(s,"parent-open",d);
    int rc=0,count=0; bool found=false;
    for(;;){
        SceIoDirent e={0};int k=sceIoDread(d,&e);
        if(k<0){rc=pa_bad(s,"parent-read",k);break;}if(!k)break;
        if(++count>8192||!memchr(e.d_name,0,sizeof e.d_name)){rc=pa_bad(s,"parent-shape",0);break;}
        if(strcmp(e.d_name,name))continue;
        found=dir?!!SCE_S_ISDIR(e.d_stat.st_mode):!!SCE_S_ISREG(e.d_stat.st_mode);break;
    }
    int c=sceIoDclose(d);if(c<0&&!rc)rc=pa_bad(s,"parent-close",c);
    return !rc&&!found?pa_bad(s,"path-missing-or-type",0):rc;
}
static bool pa_direct(const char *parent,const char *path,const char *name){
    size_t n=strlen(parent);return n?(!strncmp(parent,path,n)&&path[n]=='/'&&!strcmp(path+n+1,name)):!strcmp(path,name);
}
/* Enumerate the entire small admitted layout. Reject extra files/dirs, all
 * links, duplicate names, missing members, type or size mismatches. Platform
 * may consume its generated head during promotion; if present it is verified. */
static int pa_shape(pa_io *s,const char *root,const wb_patch_file *rows,bool need_head,bool *head){
    unsigned seen_dirs=1u,seen=0;*head=false;bool work=false;
    for(unsigned i=0;i<PA_NDIR;i++){
        if(!(seen_dirs&(1u<<i)))continue;
        char dir[PA_PATH];if(!pa_join(dir,root,pa_dirs[i]))return pa_bad(s,"path-limit",0);
        int d=sceIoDopen(dir),rc=0;if(d<0)return pa_bad(s,"tree-open",d);
        for(int entries=0;;){
            SceIoDirent e={0};int k=sceIoDread(d,&e);
            if(k<0){rc=pa_bad(s,"tree-read",k);break;} if(!k)break;
            if(++entries>64||!memchr(e.d_name,0,sizeof e.d_name)){rc=pa_bad(s,"tree-limit",0);break;}
            if(!strcmp(e.d_name,".")||!strcmp(e.d_name,".."))continue;
            bool ok=false;
            for(unsigned j=1;j<PA_NDIR;j++)if(pa_direct(pa_dirs[i],pa_dirs[j],e.d_name)){
                if(SCE_S_ISDIR(e.d_stat.st_mode)&&!(seen_dirs&(1u<<j))){seen_dirs|=1u<<j;ok=true;}break;
            }
            for(unsigned j=0;j<WB_PATCH_FILE_COUNT&&!ok;j++)if(pa_direct(pa_dirs[i],rows[j].path,e.d_name)){
                if(SCE_S_ISREG(e.d_stat.st_mode)&&(uint64_t)e.d_stat.st_size==rows[j].bytes&&!(seen&(1u<<j))){seen|=1u<<j;ok=true;}break;
            }
            if(pa_direct(pa_dirs[i],PA_HEAD,e.d_name)&&SCE_S_ISREG(e.d_stat.st_mode)&&e.d_stat.st_size==WB_HEAD_SIZE&&!*head){*head=true;ok=true;}
            if(!need_head&&pa_direct(pa_dirs[i],PA_WORK,e.d_name)&&SCE_S_ISREG(e.d_stat.st_mode)&&e.d_stat.st_size==PA_WORK_SIZE&&!work){work=true;ok=true;}
            if(!ok){rc=pa_bad(s,"tree-unknown-type-or-size",0);break;}
        }
        int c=sceIoDclose(d);if(c<0&&!rc)rc=pa_bad(s,"tree-close",c);if(rc)return rc;
    }
    if(seen!=(1u<<WB_PATCH_FILE_COUNT)-1u||(need_head&&!*head))return pa_bad(s,"tree-missing-member",0);
    return WB_OK;
}
static int pa_stopped(pa_io *s){
    SceUID id=0;int rc=sceAppMgrGetIdByName(&id,WB_PATCH_TITLE);
    return (uint32_t)rc==UINT32_C(0x80802012)?WB_OK:pa_bad(s,rc==0&&id>0?"game-running":"game-state-unknown",rc);
}
/* The single source fd is used for verify AND copy. Destination is precreated
 * only inside the exclusively-owned stage. Short reads/writes loop; a negative,
 * zero, or oversized transfer is never a successful hash/commit. */
static int pa_member(pa_io *s,const wb_patch_file *row,const char *src,const char *dst,bool progress){
    int in=-1,out=-1,rc=0;uint64_t pos=0;wb_sha256 h;wb_sha256_init(&h);
    if(src){in=sceIoOpen(src,SCE_O_RDONLY,0);if(in<0)return pa_bad(s,"member-open",in);}
    else if(!row->embedded)return pa_bad(s,"no-embedded-source",0);
    if(dst){
        SceIoStat st={0};int sr=sceIoGetstat(dst,&st);
        if((uint32_t)sr!=PA_ENOENT)rc=pa_bad(s,"stage-not-fresh",sr);
        else {out=sceIoOpen(dst,SCE_O_WRONLY|SCE_O_CREAT,0666);if(out<0)rc=pa_bad(s,"stage-open",out);}
    }
    while(!rc&&pos<row->bytes){
        unsigned n=(unsigned)(row->bytes-pos>PA_BUF?PA_BUF:row->bytes-pos);
        if(in>=0){int k=sceIoRead(in,s->buf,n);if(k<=0||(unsigned)k>n){rc=pa_bad(s,"member-read",k);break;}n=(unsigned)k;}
        else memcpy(s->buf,row->embedded+(size_t)pos,n);
        for(unsigned off=0;out>=0&&off<n;){
            int k=sceIoWrite(out,s->buf+off,n-off);if(k<=0||(unsigned)k>n-off){rc=pa_bad(s,"stage-write",k);break;}off+=(unsigned)k;
        }
#ifndef WB_FAST_SHA_UPDATE
#define WB_FAST_SHA_UPDATE(c,p,n) wb_sha256_update((c),(p),(n))
#endif
        if(!rc){WB_FAST_SHA_UPDATE(&h,s->buf,n);pos+=n;if(progress&&wb_app_count_progress(n)!=WB_OK)rc=pa_bad(s,"progress-disconnected",0);}
    }
    if(!rc&&in>=0){unsigned char extra;int k=sceIoRead(in,&extra,1);if(k!=0)rc=pa_bad(s,"member-length",k);}
    unsigned char raw[32];char hex[65];wb_sha256_final(&h,raw);wb_sha_hex(raw,32,hex);
    if(!rc&&strcmp(hex,row->sha))rc=pa_bad(s,"member-sha256",0);
    if(out>=0){
        if(!rc){int k=sceIoSyncByFd(out,0);if(k<0)rc=pa_bad(s,"stage-sync",k);}
        int k=sceIoClose(out);if(!rc&&k<0)rc=pa_bad(s,"stage-close",k);
    }
    if(in>=0){int k=sceIoClose(in);if(!rc&&k<0)rc=pa_bad(s,"source-close",k);}
    return rc;
}
static int pa_version(pa_io *s,int *base){
    unsigned char raw[PA_SFO];size_t n=0;wb_sfo sf;char title[16],ver[16];
    if(pa_child(s,PA_INST,"sce_sys",true)||pa_child(s,PA_INST "/sce_sys","param.sfo",false))return WB_E_STATE;
    int fd=sceIoOpen(PA_INST "/sce_sys/param.sfo",SCE_O_RDONLY,0);if(fd<0)return pa_bad(s,"sfo-open",fd);
    int rc=0;
    for(;;){
        int k=sceIoRead(fd,raw+n,sizeof raw-n);if(k<0||(size_t)k>sizeof raw-n){rc=pa_bad(s,"sfo-read",k);break;}
        if(!k)break;
        n+=(size_t)k;if(n==sizeof raw){rc=pa_bad(s,"sfo-limit",0);break;}
    }
    int k=sceIoClose(fd);if(!rc&&k<0)rc=pa_bad(s,"sfo-close",k);
    if(rc)return rc;
    if(wb_sfo_parse(&sf,raw,n)!=WB_OK||!wb_sfo_unambiguous(&sf)||wb_sfo_get(&sf,"TITLE_ID",title,sizeof title)!=WB_OK||
       wb_sfo_get(&sf,"APP_VER",ver,sizeof ver)!=WB_OK||strcmp(title,WB_PATCH_TITLE))return pa_bad(s,"installed-identity",0);
    SceIoStat boot_st={0};
    const bool have_boot=sceIoGetstat(PA_INST "/eboot.bin",&boot_st)>=0&&SCE_S_ISREG(boot_st.st_mode);
    int fallback=-1;
    for(unsigned i=0;i<WB_PATCH_BASE_COUNT;i++)if(!strcmp(ver,WB_PATCH_BASE_SFO_AT(i))){
        if(fallback<0)fallback=(int)i;
        if(have_boot&&(uint64_t)boot_st.st_size==wb_patch_bases[i][0].bytes){*base=(int)i;return WB_OK;}
    }
    if(fallback>=0){*base=fallback;return WB_OK;}
    return pa_bad(s,!strcmp(ver,WB_PATCH_VERSION)?"already-target-version":"unsupported-base",0);
}
static uint64_t pa_total(const wb_patch_file *r){uint64_t size=0;for(unsigned i=0;i<WB_PATCH_FILE_COUNT;i++)size+=r[i].bytes;return size;}
static int pa_image(pa_io *s,const char *root,const wb_patch_file *r,const wb_patch_file *generated,bool stage){
    bool head;int rc=pa_shape(s,root,r,stage,&head);
    for(unsigned i=0;!rc&&i<WB_PATCH_FILE_COUNT;i++){
        char p[PA_PATH];rc=pa_join(p,root,r[i].path)?pa_member(s,&r[i],p,NULL,true):pa_bad(s,"path-limit",0);
    }
    if(!rc&&head){
        char p[PA_PATH];rc=pa_join(p,root,PA_HEAD)?pa_member(s,generated,p,NULL,false):pa_bad(s,"path-limit",0);
    }
    return rc;
}
static int pa_error(wb_out *out,const pa_io *s,const char *phase){
    (void)wb_out_printf(out,"ERR app-patch phase=%s reason=%s native=0x%08x\n",phase,s->why?s->why:"unknown",(unsigned)s->raw);
    return WB_E_STATE;
}
static int wb_app_patch_execute(const char *incoming,bool apply,wb_out *out){
    pa_io ctx={0};pa_io *s=&ctx;int base=-1,rc=0;
    const char *phase="preflight";bool ours=false,issued=false;
    unsigned char headbytes[WB_HEAD_SIZE],raw[32];char headhex[65];wb_sha256 h;
    wb_patch_file head={PA_HEAD,WB_HEAD_SIZE,headhex,headbytes};
    if(!pa_input_ok(incoming))rc=pa_bad(s,"input-path",0);
    if(!rc&&(!WB_PATCH_READY_OK()))rc=pa_bad(s,"session-gate",0);
    if(!rc)rc=pa_stopped(s);
    if(!rc)rc=pa_child(s,"ux0:/","app",true);
    if(!rc)rc=pa_child(s,"ux0:/app",WB_PATCH_TITLE,true);
    if(!rc)rc=pa_version(s,&base);
    if(!rc)rc=pa_child(s,"ux0:/","VITA-POC",true);
    if(!rc)rc=pa_child(s,WB_INCOMING,incoming+sizeof(WB_INCOMING),false);
    if(!rc&&wb_head_build(headbytes,sizeof headbytes,WB_PATCH_TITLE,NULL)!=WB_OK)rc=pa_bad(s,"head-generation",0);
    if(rc)return pa_error(out,s,phase);
    wb_sha256_init(&h);wb_sha256_update(&h,headbytes,sizeof headbytes);wb_sha256_final(&h,raw);wb_sha_hex(raw,32,headhex);
    const wb_patch_file *from=wb_patch_bases[base],*to=wb_patch_target;
    const uint64_t basesz=pa_total(from),tsz=pa_total(to);
    memset(&wb_app_progress,0,sizeof wb_app_progress);wb_app_progress.out=out;wb_app_progress.last=now_ms();
    if(!(s->buf=malloc(PA_BUF)))rc=pa_bad(s,"nomem",0);
    if(!rc&&WB_APP_BUDGET(tsz+WB_HEAD_SIZE+8u*1024u*1024u,out)!=WB_OK)rc=pa_bad(s,"space-budget",0);
    if(!rc){
        wb_app_phase("copy",basesz+to[0].bytes);phase="base";
        rc=pa_image(s,PA_INST,from,&head,false);
    }
    if(!rc){phase="input";rc=pa_member(s,&to[0],incoming,NULL,true);}
    if(!rc&&apply){
        phase="stage";
        if(!WB_PATCH_READY_OK())rc=pa_bad(s,"session-gate",0);
        if(!rc)rc=pa_stopped(s);
        if(!rc)rc=pa_child(s,"ux0:/","data",true);
        if(!rc)rc=pa_child(s,"ux0:/data",WB_TITLE_ID,true);
        if(!rc){int k=sceIoMkdir(PA_STAGE,0777);if(k<0)rc=pa_bad(s,"stage-exists-or-unavailable",k);else ours=true;}
        for(unsigned j=1;!rc&&j<PA_NDIR;j++){
            char p[PA_PATH];if(!pa_join(p,PA_STAGE,pa_dirs[j]))rc=pa_bad(s,"path-limit",0);
            else {int k=sceIoMkdir(p,0777);if(k<0)rc=pa_bad(s,"stage-dir",k);}
        }
        wb_app_phase("validate",2*tsz+basesz);
        for(unsigned i=0;!rc&&i<WB_PATCH_FILE_COUNT;i++){
            char dst[PA_PATH],asset[PA_PATH];const char *src=NULL;
            if(!pa_join(dst,PA_STAGE,to[i].path)||!pa_join(asset,PA_INST,to[i].path)){rc=pa_bad(s,"path-limit",0);break;}
            if(i==0)src=incoming;else if(!to[i].embedded)src=asset;
            rc=pa_member(s,&to[i],src,dst,true);
        }
        if(!rc)rc=pa_member(s,&head,NULL,PA_STAGE "/" PA_HEAD,false);
        phase=rc?phase:"recheck-base";
        if(!rc)rc=pa_image(s,PA_INST,from,&head,false);
        phase=rc?phase:"verify-stage";
        if(!rc)rc=pa_image(s,PA_STAGE,to,&head,true);
        if(!rc)rc=pa_stopped(s);
        if(!rc&&!WB_PATCH_COMMIT_OK())rc=pa_bad(s,"commit-gate",0);
        if(!rc){
            int detail=0;issued=true;phase="publish-outcome-unknown";
            int k=wb_vita_promote_stage(PA_STAGE,true,&detail);
            if(k!=WB_OK)rc=pa_bad(s,"promoter",detail?detail:k);
        }
        if(!rc){phase="post-verify-outcome-unknown";wb_app_phase("extract",tsz);rc=pa_image(s,PA_INST,to,&head,false);}
    }
    /* Never recursively delete a directory discovered on the device. A failed
     * write or uncertain promoter may leave evidence or an in-use stage. Keep
     * that private directory, reject any new apply while present, never replay. */
    if(rc&&ours&&!issued)(void)wb_out_puts(out,"patch-note private-stage-retained no-promotion\n");
    free(s->buf);
    if(rc)return pa_error(out,s,phase);
    return wb_out_printf(out,"OK app-patch%s title=%s base=%s app_ver=%s eboot_sha256=%s\n",
        apply?"":"-plan",WB_PATCH_TITLE,wb_patch_base_versions[base],WB_PATCH_VERSION,to[0].sha);
}
