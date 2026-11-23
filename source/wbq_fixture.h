#ifndef WBQ_FIXTURE_H
#define WBQ_FIXTURE_H
#include "wbq_io.h"
#define WQFX WBQ_STORE "/wbq2-fixture"
#define WQFX_PRIVATE WBQ_STORE "/wbq2-fixture-copy"
#define WQFX_PUB WBQ_STORE "/fixture-public.txt"
#define WQFX_SEAL WBQ_STORE "/fixture-seal.txt"
static inline int wq_count_only(const char *path,void *ctx){
 if(strcmp(path,WQFX_PRIVATE))return WB_E_STATE;
 (*(int*)ctx)++;return WB_OK;
}
static inline int wq_fx_run(const char *token,char *log,size_t cap){
 const char *const data[]={"inert fixture eboot, not executable",NULL,"inert generated-head fixture","inert payload data, not executable"};
 uint8_t *sfo=malloc(65536);size_t n=0;char ver[6],receipt[WBQ_CAP]={0},path[WQPATH],extra[WQPATH];wbq_manifest m={0};
 int rc=WB_E_NOMEM,calls=0,passed=0;size_t used=0;
 int a=snprintf(log,cap,"S1-CHECK build=%s run=%s fixture=isolated\n",WB_BUILD_TAG,token);
 if(a<0 || (size_t)a>=cap){free(sfo);return WB_E_LIMIT;}used=(size_t)a;
 if(!sfo)goto done;
 rc=wq_read(WBQ_INSTALLED,sfo,65536,&n);if(!rc)rc=wbq_identity(sfo,n,ver);if(rc)goto done;
 rc=wq_path(extra,WQFX,"extra.txt");if(rc)goto done;
 wq_cleanup(WQFX);if(sceIoMkdir(WQFX,WQ_DIR_MODE)<0){rc=WB_E_STAGE;goto done;}
 rc=wq_dirs(WQFX);if(rc)goto clean;
 for(unsigned i=0;i<4;i++){
  const uint8_t *p=i==1?sfo:(const uint8_t*)data[i];size_t k=i==1?n:strlen(data[i]);
  if((rc=wbq_bytes(&m,i,p,k)) || (rc=wq_path(path,WQFX,wbq_names[i])) || (rc=wq_save(path,p,k)))goto clean;
 }
 rc=wbq_format(&m,ver,receipt);if(rc)goto clean;
 if((rc=wq_save(WQFX_PUB,receipt,strlen(receipt))) || (rc=wq_save(WQFX_SEAL,receipt,strlen(receipt))))goto clean;
 /* All changes below are constant data in a dedicated isolated fixture. */
 for(unsigned test=0;test<11;test++){
  static const char *const lbl[]={"original","changed","missing","extra","legacy","absent","seal-mismatch","not-newer","sfo-content","generated-head","payload-content"};
  int expected[]={0,WB_E_SHA,WB_E_STAGE,WB_E_STAGE,WB_E_STATE,WB_E_STATE,WB_E_STATE,WB_E_VERSION,WB_E_SHA,WB_E_SHA,WB_E_SHA};
  rc=wq_path(path,WQFX,wbq_names[0]);if(rc)goto clean;
  if(test==1){rc=wq_save(path,"different inert text",20);}
  if(test==2){rc=sceIoRemove(path)<0?WB_E_IO:0;}
  if(test==3){rc=wq_save(path,data[0],strlen(data[0]));if(!rc)rc=wq_save(extra,"x",1);}
  if(test==4){rc=sceIoRemove(extra)<0?WB_E_IO:0;if(!rc)rc=wq_save(WQFX_PUB,"WBQ1 01.32\n",11);}
  if(test==5){rc=sceIoRemove(WQFX_PUB)<0?WB_E_IO:0;}
  if(test==6){rc=wq_save(WQFX_PUB,receipt,strlen(receipt));if(!rc)rc=wq_save(WQFX_SEAL,"other",5);}
  if(test==7){rc=wq_save(WQFX_SEAL,receipt,strlen(receipt));}
  if(test==8){
   rc=wq_path(path,WQFX,wbq_names[1]);
   if(!rc){int fd=sceIoOpen(path,SCE_O_WRONLY|SCE_O_APPEND,0);if(fd<0)rc=WB_E_IO;
    else {rc=wq_write(fd,"z",1);if(sceIoClose(fd)<0)rc=WB_E_IO;}}
  }
  if(test==9){
   rc=wq_path(path,WQFX,wbq_names[1]);if(!rc)rc=wq_save(path,sfo,n);
   if(!rc)rc=wq_path(path,WQFX,wbq_names[2]);
   if(!rc)rc=wq_save(path,"head x",6);
  }
  if(test==10){
   rc=wq_path(path,WQFX,wbq_names[2]);if(!rc)rc=wq_save(path,data[2],strlen(data[2]));
   if(!rc)rc=wq_path(path,WQFX,wbq_names[3]);
   if(!rc)rc=wq_save(path,"payload x",9);
  }
  if(rc)goto clean;
  const int was=calls;int got=wq_final(WQFX_PUB,WQFX_SEAL,WQFX,WQFX_PRIVATE,test==7?ver:"00.00",wq_count_only,&calls);
  int ok=got==expected[test] && calls-was==(test==0?1:0);
  a=snprintf(log+used,cap-used,"%s rc=%d expected=%d handoff=%d %s\n",lbl[test],got,expected[test],calls-was,ok?"PASS":"FAIL");
  if(a<0 || (size_t)a>=cap-used){rc=WB_E_LIMIT;goto clean;}used+=(size_t)a;
  if(!ok){rc=WB_E_STATE;goto clean;}passed++;
 }
clean:
 (void)sceIoRemove(extra);wq_cleanup(WQFX);wq_cleanup(WQFX_PRIVATE);(void)sceIoRemove(WQFX_PUB);(void)sceIoRemove(WQFX_SEAL);
done:
 free(sfo);a=snprintf(log+used,cap-used,"result=%s tests=%d/11 native_promote_calls=0 rc=%d\n",rc==0 && passed==11?"PASS":"FAIL",passed,rc);
 if(a<0 || (size_t)a>=cap-used)return WB_E_LIMIT;
 return rc;
}
#endif
