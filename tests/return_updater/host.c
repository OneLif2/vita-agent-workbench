/* Exercise the real updater main with synthetic files, injected Vita OS
 * returns, and an inert promoter. No process replacement, network, or Vita. */
#define main legacy_s1_test
#define sceIoGetstat fixture_getstat
#define sceIoRemove fixture_remove
#include "../s1/host.c"
#undef main
#undef sceIoGetstat
#undef sceIoRemove
#include <assert.h>
#include <errno.h>
int sceIoGetstat(const char *p,SceIoStat *s);
int sceIoRemove(const char *p);
#define main updater_under_test
#include "../../updater/main.c"
#undef main
static const char *mode;
static int handoffs,relaunches,visible_at_relaunch;
static wb_r1_ticket expected;
static int eqmode(const char *m){return !strcmp(m,mode);}
int sceIoRemove(const char *p){
 if(eqmode("intent-unlink-error") && !strcmp(p,WB_R1_INTENT))return -1;
 int rc=fixture_remove(p);return rc<0 && errno==ENOENT?(int)UINT32_C(0x80010002):rc;
}
int sceIoGetstat(const char *p,SceIoStat *s){int rc=fixture_getstat(p,s);return rc<0 && errno==ENOENT?(int)UINT32_C(0x80010002):rc;}
int sceIoRename(const char *a,const char *b){
 if(eqmode("proof-rename-error") && !strcmp(b,WB_R1_SUCCESS))return -1;
 char dst[1024];strcpy(dst,native(b));return rename(native(a),dst);
}
int sceSysmoduleLoadModuleInternalWithArg(SceSysmoduleModuleId i,SceSize n,void *v,SceSysmoduleOpt *o){(void)i;(void)n;(void)v;(void)o;return 0;}
int sceSysmoduleUnloadModuleInternalWithArg(SceSysmoduleModuleId i,SceSize n,void *v,SceSysmoduleOpt *o){return sceSysmoduleLoadModuleInternalWithArg(i,n,v,o);}
int sceSysmoduleLoadModuleInternal(SceSysmoduleModuleId i){(void)i;return 0;}
int sceSysmoduleUnloadModuleInternal(SceSysmoduleModuleId i){(void)i;return 0;}
int scePromoterUtilityInit(void){return 0;}
int scePromoterUtilityExit(void){return 0;}
void sceKernelDelayThread(SceUInt u){(void)u;}
int scePromoterUtilityPromotePkgWithRif(const char *p,int sync){
 assert(!strcmp(p,WBQ_FINAL) && sync==1);handoffs++;
 if(eqmode("post-measure-receipt-rewrite"))
  assert(wq_save(WB_PENDING_PATH,"changed-after-verified-handoff",30)==0);
 return 0;
}
int scePromoterUtilityGetState(int *s){*s=0;return 0;}
int scePromoterUtilityGetResult(int *out){*out=eqmode("native-error")?-42:0;return 0;}
int sceRtcGetCurrentTick(SceRtcTick *t){t->tick=eqmode("expired")?expected.expires:expected.issued+1;return eqmode("rtc-error")?-1:0;}
int sceAppMgrDestroyOtherApp(void){return 0;}
int sceAppMgrLaunchAppByUri(int flags,const char *uri){assert(flags==0x20000);assert(!strcmp(uri,"psgm:play?titleid=INAP00018"));
 wb_r1_ticket out;size_t n=0;relaunches++;
 visible_at_relaunch= !wq_read(WB_R1_SUCCESS,&out,sizeof out,&n) && n==sizeof out && memcmp(&out,&expected,n)==0;
 return eqmode("relaunch-error")?-7:0;
}
void sceKernelExitProcess(int rc){assert(rc==0);}
int main(int argc,char **argv){
 assert(argc==2);mode=argv[1];
 char receipt[WBQ_CAP],copy[WBQ_CAP],p[WQPATH];
 wbq_manifest manifest;
 assert(wq_measure(WB_STAGE_DIR,NULL,&manifest)==0);
 assert(wbq_format(&manifest,TEST_TARGET,receipt)==0);
 assert(wq_installed_receipt(WB_STAGE_DIR,TEST_TARGET,copy)==0 && !strcmp(copy,receipt));
 /* Installed applications may have OS metadata not present in the staged VPK. */
 assert(!wq_path(p,WB_STAGE_DIR,"platform-metadata"));assert(!wq_save(p,"X",1));
 assert(!wq_installed_receipt(WB_STAGE_DIR,TEST_TARGET,copy) && !strcmp(copy,receipt));
 assert(wq_shape(WB_STAGE_DIR)!=WB_OK);assert(sceIoRemove(p)==0);
 assert(!wq_save(WB_PENDING_PATH,receipt,strlen(receipt)));assert(!wq_save(WBQ_SEAL,receipt,strlen(receipt)));
 char requested[WBQ_CAP];strcpy(requested,receipt);
 if(eqmode("other-receipt"))requested[11]=requested[11]=='a'?'b':'a';
 char pin[65];memset(pin,'A',64);pin[64]=0;
 assert(wb_r1_make(&expected,100000,eqmode("other-source")?"01.32":WB_VERSION,"0123456789ABCDEF",
        "ABADEEFF00112233445566778899AABB",pin,pin,requested));
 assert(!wq_save(WB_R1_SUCCESS,&expected,sizeof expected)); /* stale file, always purged */
 if(!eqmode("no-consent")){
  size_t len=eqmode("truncated")?sizeof expected-1:sizeof expected;
  assert(!wq_save(WB_R1_INTENT,&expected,len));
 }
 if(eqmode("stale-stage"))assert(!wq_save(WB_STAGE_DIR "/eboot.bin","bad",3));
 if(eqmode("selfcheck"))assert(!wq_save(WBQ_TEST,"0123456789ABCDEF",16));
 assert(updater_under_test()==0 && relaunches==1);
 bool success=eqmode("approved") || eqmode("post-measure-receipt-rewrite");
 int expect_handoff=(eqmode("selfcheck")||eqmode("stale-stage"))?0:1;
 SceIoStat st;
 assert(handoffs==expect_handoff && visible_at_relaunch==(success||eqmode("relaunch-error")));
 assert((sceIoGetstat(WB_R1_SUCCESS,&st)==0)==success);
 assert(sceIoGetstat(WB_R1_DRAFT,&st)<0);
 if(!eqmode("intent-unlink-error"))assert(sceIoGetstat(WB_R1_INTENT,&st)<0);
 printf("PASS %s: native_calls=%d launch_calls=%d proof_at_launch=%d retained=%d\n",mode,handoffs,relaunches,visible_at_relaunch,success);
 return 0;
}
