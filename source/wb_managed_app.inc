/* Eligible installed apps only. Read typed identity under ux0:/app, never a
 * caller path. Use the platform's title-delete lifecycle, never rm or SQL. */
#include "wb_app_remove_policy.h"
#include <stdlib.h>
#include <psp2/kernel/processmgr.h>

typedef struct {char id[10],ver[6],sfo[65],boot[65];} wb_managed_id;
typedef struct {wb_managed_id app;char token[65];uint64_t time;} wb_managed_plan;
static wb_managed_plan wb_remove_plan;
static uint64_t wb_remove_serial;
void wb_vita_forget_remove_plan(void){memset(&wb_remove_plan,0,sizeof wb_remove_plan);}

static int wbm_ident_file(const char *p,int sfo,wb_managed_id *id,bool status_query){
    SceIoStat st={0};int statrc=sceIoGetstat(p,&st);
    if(statrc<0)return statrc;
    if(!SCE_S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>(sfo?65536:128*1024*1024))return WB_E_FORMAT;
    wb_reader rd;wb_vfile vf;int rc=wb_vita_reader_open(p,&rd,&vf);
    if(rc!=WB_OK)return rc;
    size_t cap=sfo?(size_t)st.st_size:8192;
    unsigned char *buf=malloc(cap);wb_sha256 h;uint8_t sum[32];wb_sha256_init(&h);
    if(!buf)rc=WB_E_NOMEM;
    if(rd.size!=(uint64_t)st.st_size)rc=WB_E_FORMAT;
    for(uint64_t off=0;rc==WB_OK&&off<rd.size;){
        size_t n=rd.size-off<cap?(size_t)(rd.size-off):cap;
        rc=rd.read_at(rd.ctx,off,buf,n);if(rc!=WB_OK)break;
        if(sfo){
            wb_sfo x;char tid[10],cat[8];char *v=id->ver;
            if(wb_sfo_parse(&x,buf,n)!=WB_OK||!wb_sfo_unambiguous(&x)||
               wb_sfo_get(&x,"TITLE_ID",tid,sizeof tid)!=WB_OK||strcmp(tid,id->id)||
               wb_sfo_get(&x,"CATEGORY",cat,sizeof cat)!=WB_OK||
               wb_sfo_get(&x,"APP_VER",v,sizeof id->ver)!=WB_OK||strlen(v)!=5||
               v[2]!='.'||strspn(v,"0123456789")!=2||strspn(v+3,"0123456789")!=2){
                rc=WB_E_FORMAT;break;
            }
            /* WB Lifecycle's real frontend is gdc; its gdd companion is not
             * an independently inspectable/removable app. Recognize only
             * this known frontend/version pair for read-only status. */
            if(strcmp(cat,"gd") &&
               (!status_query || strcmp(id->id,"WBLC00079") || strcmp(cat,"gdc") ||
                (strcmp(v,"01.00") && strcmp(v,"01.01") && strcmp(v,"01.02")))){
                rc=WB_E_FORMAT;break;
            }
        }
        wb_sha256_update(&h,buf,n);off+=n;
    }
    free(buf);wb_vita_reader_close(&vf);
    if(rc==WB_OK){wb_sha256_final(&h,sum);wb_sha_hex(sum,32,sfo?id->sfo:id->boot);}
    return rc;
}
static int wbm_inspect(const char *title,wb_managed_id *id,wbu_note *n,bool status_query){
    char path[96],sfo[96],exe[96],sp[96];memset(id,0,sizeof *id);memcpy(id->id,title,10);
    snprintf(path,sizeof path,"ux0:/app/%s",title);snprintf(sfo,sizeof sfo,"ux0:/app/%s/sce_sys/param.sfo",title);
    snprintf(exe,sizeof exe,"ux0:/app/%s/eboot.bin",title);snprintf(sp,sizeof sp,"vs0:/app/%s",title);
    n->step="system-path";n->disk=wbu_disk(sp,true,-1);if(n->disk!=0)return -1;
    n->step="control-path";n->disk=wbu_disk("ux0:/app/" WB_TITLE_ID,true,-1);if(n->disk!=1)return -1;
    n->disk=wbu_disk("ux0:/app/" WBU_ABS_ID,true,-1);if(n->disk!=0)return -1;
    wbu_query hit=wbu_q(WB_TITLE_ID),miss=wbu_q(WBU_ABS_ID);
    n->step="db-present-control";n->rc=hit.rc;n->value=hit.value;if(hit.rc!=0)return -1;
    n->step="db-absent-control";n->rc=miss.rc;n->value=miss.value;if(!wbu_missing_signature(hit,miss))return -1;
    wbu_query q=wbu_q(title);n->step="title-db";n->rc=q.rc;n->value=q.value;
    bool present=miss.rc<0?(q.rc==0&&(q.value>=0||q.value==INT_MIN)):wbu_equal(q,hit);
    if(!present&&!wbu_equal(q,miss))return -1;
    n->step="title-dir";n->disk=wbu_disk(path,true,-1);if(n->disk!=(int)present)return -1;
    n->step="title-sfo";n->disk=wbu_disk(sfo,false,-1);if(n->disk!=(int)present)return -1;
    n->step="title-eboot";n->disk=wbu_disk(exe,false,-1);if(n->disk!=(int)present)return -1;
    if(!present)return 0;
    n->step="sfo-identity";if((n->rc=wbm_ident_file(sfo,1,id,status_query))!=WB_OK)return -1;
    n->step="eboot-identity";if((n->rc=wbm_ident_file(exe,0,id,false))!=WB_OK)return -1;
    return 1;
}
static uint64_t wbm_now(void){return (uint64_t)sceKernelGetProcessTimeWide()/1000u;}
static bool wbm_fresh(uint64_t start){uint64_t t=wbm_now();return t>=start&&t-start<=120000;}
static void wbm_token(const wb_managed_id *id,const char *run){
    uint8_t d[32];wb_sha256 h;wb_sha256_init(&h);uint64_t seq=++wb_remove_serial;
    wb_remove_plan.app=*id;wb_remove_plan.time=wbm_now();
    wb_sha256_update(&h,id,sizeof *id);wb_sha256_update(&h,run,strlen(run));
    wb_sha256_update(&h,&seq,sizeof seq);wb_sha256_update(&h,&wb_remove_plan.time,sizeof wb_remove_plan.time);
    wb_sha256_final(&h,d);wb_sha_hex(d,32,wb_remove_plan.token);
}
int wb_vita_managed_app_command(const char *title,int action,const char *token,const char *run,wb_out *out,int *status){
    wb_managed_plan prior=wb_remove_plan;wb_managed_id id;wbu_note n={"target",0,0,0,false};
    bool paf=false,mod=false,init=false,ok=false;int seen=-1,st,r;*status=1;
    if(action==1||action==2)wb_vita_forget_remove_plan();
    if(action<0||action>2||!wb_remove_id(title)||!run||strlen(run)!=16)goto end;
    if(action==2){n.step="token";if(!wb_remove_hex(token)||!prior.token[0]||strcmp(token,prior.token)||
         strcmp(title,prior.app.id)||!wbm_fresh(prior.time))goto end;}
    n.step="paf";if((n.rc=load_paf())<0)goto end;paf=true;
    n.step="load";if((n.rc=sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL))<0)goto end;mod=true;
    n.step="init";if((n.rc=scePromoterUtilityInit())<0)goto end;init=true;
    seen=wbm_inspect(title,&id,&n,action==0);if(seen<0)goto end;
    if(action==0){ok=true;goto end;}n.step="already-absent";if(seen!=1)goto end;
    if(action==1){ok=true;goto end;}
    n.step="identity-changed";if(memcmp(&prior.app,&id,sizeof id))goto end;
    n.step="pre-state";st=-1;n.rc=scePromoterUtilityGetState(&st);n.value=st;if(n.rc<0||st!=0)goto end;
    n.step="token-expired";if(!wbm_fresh(prior.time))goto end;
    n.step="submit";n.issued=true;n.rc=scePromoterUtilityDeletePkg(title);if(n.rc!=0)goto end;
    n.step="poll";
    for(unsigned i=0;i<WB_INSTALL_MS/50u;i++){
        st=-1;n.rc=scePromoterUtilityGetState(&st);n.value=st;if(n.rc<0||st<0)goto end;
        if(!st)break;
        sceKernelDelayThread(50000);
    }
    if(n.value!=0){n.step="timeout";goto end;}
    n.step="result";r=-1;n.rc=scePromoterUtilityGetResult(&r);n.value=r;if(n.rc<0||r!=0)goto end;
    seen=wbm_inspect(title,&id,&n,false);if(seen<0)goto end;if(seen!=0){n.step="still-installed";goto end;}
    ok=true;
end:
    if(init&&(r=scePromoterUtilityExit())<0&&ok){n.step="exit";n.rc=r;ok=false;}
    if(mod&&(r=sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL))<0&&ok){n.step="unload";n.rc=r;ok=false;}
    if(paf&&(r=unload_paf())<0&&ok){n.step="paf-exit";n.rc=r;ok=false;}
    if(!ok)return wb_out_printf(out,"ERR app-uninstall-gate phase=%s rc=%08X value=%08X disk=%08X issued=%d\n",
                    n.step,(unsigned)n.rc,(unsigned)n.value,(unsigned)n.disk,n.issued?1:0);
    *status=0;
    if(action==1){wbm_token(&id,run);return wb_out_printf(out,
        "app uninstall-plan title=%s app_ver=%s sfo_sha256=%s eboot_sha256=%s token=%s\n",title,id.ver,id.sfo,id.boot,wb_remove_plan.token);}
    if(action==2)return wb_out_printf(out,"OK app-uninstall title=%s state=absent\n",title);
    return seen?wb_out_printf(out,"app title=%s state=installed app_ver=%s\n",title,id.ver):
                wb_out_printf(out,"app title=%s state=absent\n",title);
}
