/* SSH-Vita 1.4.2 only. Included in wb_vita_install.c to share the existing PAF
 * loader. No caller path, generic delete API, recursive FS change or fallback.
 * API: https://docs.vitasdk.org/group__ScePromoterUtilUser.html */
#include <psp2/io/stat.h>
#include <limits.h>
#include "wb_out.h"
#include "wb_sha256.h"
#include "wb_sfo.h"
#define WBU_ID "VSSH00001"
#define WBU_ROOT "ux0:/app/" WBU_ID
#define WBU_SFO WBU_ROOT "/sce_sys/param.sfo"
#define WBU_BOOT WBU_ROOT "/eboot.bin"
#define WBU_ABS_ID "WBCZ00000"
#define WBU_NOTFOUND ((int)0x80010002u)
/* SCE_LSDB_ERROR_NOT_FOUND; calibrated rc/out from 01.71 on this Vita. */
#define WBU_LSDB_NOT_FOUND ((int)0x80101005u)
typedef struct {int rc,value;} wbu_query;
typedef struct {const char *step;int rc,value,disk;bool issued;} wbu_note;
static int wbu_disk(const char *path,bool dir,int size){
    SceIoStat st={0};int rc=sceIoGetstat(path,&st);
    if(rc==WBU_NOTFOUND)return 0;
    if(rc<0)return rc;
    return (dir?SCE_S_ISDIR(st.st_mode):SCE_S_ISREG(st.st_mode)) &&
           (size<0||st.st_size==size)?1:WB_E_FORMAT;
}
static wbu_query wbu_q(const char *id){
    wbu_query q={0,INT_MIN}; q.rc=scePromoterUtilityCheckExist(id,&q.value);return q;
}
static bool wbu_equal(wbu_query a,wbu_query b){return a.rc==b.rc&&a.value==b.value;}
/* Some SDK docs do not define the out-parameter. Compare against independent
 * physical positive/negative controls; never classify arbitrary platform I/O
 * errors as absence. Observe and report unfamiliar signatures, do not delete. */
static bool wbu_missing_signature(wbu_query hit,wbu_query miss){
    if(hit.rc!=0||(hit.value<0&&hit.value!=INT_MIN)||wbu_equal(hit,miss))return false;
    if(miss.rc==WBU_LSDB_NOT_FOUND&&miss.value==3)return true;
    if(miss.rc==WBU_NOTFOUND&&(miss.value>=0||miss.value==INT_MIN||miss.value==WBU_NOTFOUND))return true;
    if(miss.rc==0&&miss.value==WBU_NOTFOUND)return true;
    return hit.rc==0&&miss.rc==0&&((hit.value==1&&miss.value==0)||(hit.value==0&&miss.value==1));
}
static int wbu_hash_file(const char *path,unsigned bytes,const char *expected,bool check_sfo){
    wb_reader rd;wb_vfile f;int rc=wb_vita_reader_open(path,&rd,&f);
    if(rc!=WB_OK)return rc;
    wb_sha256 sh;wb_sha256_init(&sh);uint8_t buf[1024],digest[32];char hex[65];
    if(rd.size!=bytes)rc=WB_E_FORMAT;
    for(unsigned off=0;rc==WB_OK&&off<bytes;){
        size_t n=bytes-off<sizeof buf?bytes-off:sizeof buf;
        rc=rd.read_at(rd.ctx,off,buf,n);if(rc!=WB_OK)break;
        if(check_sfo){
            char title[16],ver[16];wb_sfo s;
            if(off||n!=bytes||wb_sfo_parse(&s,buf,n)!=WB_OK||!wb_sfo_unambiguous(&s)||
               wb_sfo_get(&s,"TITLE_ID",title,sizeof title)!=WB_OK||strcmp(title,WBU_ID)||
               wb_sfo_get(&s,"APP_VER",ver,sizeof ver)!=WB_OK||strcmp(ver,"01.42")){rc=WB_E_FORMAT;break;}
        }
        wb_sha256_update(&sh,buf,n);off+=(unsigned)n;
    }
    wb_vita_reader_close(&f);
    if(rc!=WB_OK)return rc;
    wb_sha256_final(&sh,digest);wb_sha_hex(digest,32,hex);
    return strcmp(hex,expected)?WB_E_FORMAT:WB_OK;
}
static int wbu_inspect(wbu_note *n){
    n->step="control-path";n->disk=wbu_disk("ux0:/app/" WB_TITLE_ID,true,-1);
    if(n->disk!=1)return -1;
    n->disk=wbu_disk("ux0:/app/" WBU_ABS_ID,true,-1);if(n->disk!=0)return -1;
    wbu_query hit=wbu_q(WB_TITLE_ID),miss=wbu_q(WBU_ABS_ID);
    n->step="db-present-control";n->rc=hit.rc;n->value=hit.value;if(hit.rc!=0)return -1;
    n->step="db-absent-control";n->rc=miss.rc;n->value=miss.value;
    if(!wbu_missing_signature(hit,miss))return -1;
    wbu_query q=wbu_q(WBU_ID);n->step="title-db";n->rc=q.rc;n->value=q.value;
    int path=wbu_disk(WBU_ROOT,true,-1);n->disk=path;
    /* When absence has a documented negative rc, CheckExist's rc distinguishes
     * present from absent; its success out-word is not an identity shared by
     * unrelated titles. If rc is zero for both states, keep exact matching. */
    bool present=miss.rc<0?(q.rc==0&&(q.value>=0||q.value==INT_MIN)):wbu_equal(q,hit);
    if(!present&&!wbu_equal(q,miss))return -1;
    n->step="title-dir";if(path<0||present!=(path==1))return -1;
    n->step="title-sfo";n->disk=wbu_disk(WBU_SFO,false,912);if(n->disk!=path)return -1;
    n->step="title-eboot";n->disk=wbu_disk(WBU_BOOT,false,181097);if(n->disk!=path)return -1;
    if(!path)return 0;
    /* From the registered upstream VPK e6363e62?758ce, not an arbitrary
     * package which reused the same title ID / edited its SFO. */
    n->step="sfo-identity";n->rc=wbu_hash_file(WBU_SFO,912,"49211daabc27fb7ff460f21aec7bb762cb476a85453318efb6094c0d7e3d3df3",true);
    if(n->rc!=WB_OK)return -1;
    n->step="eboot-identity";n->rc=wbu_hash_file(WBU_BOOT,181097,"bcf648cfa51588d44dca330049a67647c48db2f14300d093849c38efa7288f8c",false);
    return n->rc==WB_OK?1:-1;
}
int wb_vita_ssh_vita_command(const char *title,bool uninstall,wb_out *out,int *status){
    bool paf=false,mod=false,init=false;int observed=-1,ok=0,r,st;
    wbu_note n={"target",0,0,0,false};*status=1;
    if(!title||strcmp(title,WBU_ID))return wb_out_puts(out,"ERR app-target: VSSH00001 only\n");
    n.step="paf";if((n.rc=load_paf())<0)goto end;paf=true;
    n.step="load";if((n.rc=sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL))<0)goto end;mod=true;
    n.step="init";if((n.rc=scePromoterUtilityInit())<0)goto end;init=true;
    observed=wbu_inspect(&n);if(observed<0)goto end;
    if(!uninstall){ok=1;goto end;}
    if(!observed){n.step="already-absent";goto end;}
    n.step="pre-state";st=-1;n.rc=scePromoterUtilityGetState(&st);n.value=st;if(n.rc<0||st!=0)goto end;
    n.step="submit";n.issued=true;
    /* Single call. No retries, no user-supplied path/title sent to promoter. */
    n.rc=scePromoterUtilityDeletePkg(WBU_ID);if(n.rc!=0)goto end;
    n.step="poll";
    for(unsigned i=0;i<WB_INSTALL_MS/50u;i++){
        st=-1;n.rc=scePromoterUtilityGetState(&st);n.value=st;if(n.rc<0||st<0)goto end;
        if(!st)break;
        sceKernelDelayThread(50000);
    }
    if(n.value!=0){n.step="timeout";goto end;}
    n.step="result";r=-1;n.rc=scePromoterUtilityGetResult(&r);n.value=r;if(n.rc<0||r!=0)goto end;
    observed=wbu_inspect(&n);if(observed<0)goto end;
    if(observed!=0){n.step="still-installed";goto end;}
    ok=1;
end:
    /* Preserve the first failure. Never return OK if cleanup failed. */
    if(init&&(r=scePromoterUtilityExit())<0&&ok){n.step="exit";n.rc=r;ok=0;}
    if(mod&&(r=sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL))<0&&ok){n.step="unload";n.rc=r;ok=0;}
    if(paf&&(r=unload_paf())<0&&ok){n.step="paf-exit";n.rc=r;ok=0;}
    if(!ok)return wb_out_printf(out,"ERR app-uninstall-gate phase=%s rc=%08X value=%08X disk=%08X issued=%d\n",
        n.step,(unsigned)n.rc,(unsigned)n.value,(unsigned)n.disk,n.issued?1:0);
    *status=0;
    return wb_out_puts(out,uninstall?"OK app-uninstall title=VSSH00001 state=absent\n":
        observed?"app title=VSSH00001 state=installed app_ver=01.42\n":"app title=VSSH00001 state=absent\n");
}
