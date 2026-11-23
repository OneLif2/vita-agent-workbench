/* Native tests of the core's actual issue, apply, durable consume and status. */
#include <assert.h>
#include <stdarg.h>
#include <psp2/io/stat.h>
#include <psp2/rtc.h>
#include <psp2/apputil.h>
#include <psp2/kernel/rng.h>
#include "wb_return_policy.h"
#include "wb_out.h"
#undef WB_VERSION
#define WB_VERSION active_version
static const char *active_version, *stored_host;
static struct {const char *run_hex,*user_pin,*pin;} a;
static uint64_t wall,mono;
static uint64_t now_ms(void){return mono;}
static void hex(char *out,const uint8_t *b,size_t n){for(size_t i=0;i<n;i++)sprintf(out+2*i,"%02X",b[i]);}
static bool wb_ssh_existing_pin(char hp[65]){if(!stored_host)return false;strcpy(hp,stored_host);return true;}
static int wq_read(const char*,void*,size_t,size_t*);
static int wq_save(const char*,const void*,size_t);
static int wq_sealed_receipt(const char*,const char*,char*);
static int wq_installed_receipt(const char*,const char*,char*);
static int healthy_stage;
static int queued_core_check(void){return healthy_stage?WB_OK:WB_E_STATE;}
#include "wb_return_vita.h"
static const char own[]="aBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaB";
static const char host[]="dEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdEdE";
static const char *const paths[]={R1_LOCAL_PATH,WB_R1_INTENT,WB_R1_SUCCESS};
typedef struct {unsigned char data[512];size_t n;bool exists;} obj;
static obj files[3];
static char stage[WBQ_CAP],installed[WBQ_CAP],output[512],nonce[33];
static bool fail_save,fail_readback,fail_stat,fail_export,fail_remove;
static int slot(const char*p){for(int i=0;i<3;i++)if(!strcmp(p,paths[i]))return i;assert(!"unexpected path");return -1;}
#define NOENT ((int)UINT32_C(0x80010002))
static int wq_read(const char*p,void*d,size_t cap,size_t*n){
    obj*f=&files[slot(p)];if(!f->exists || cap<f->n || (fail_readback&&slot(p)==0))return WB_E_IO;
    *n=f->n;memcpy(d,f->data,*n);return WB_OK;
}
static int wq_save(const char*p,const void*b,size_t n){int i=slot(p);obj*f=&files[i];
    assert(n<=sizeof f->data);if(fail_export&&i==1)return WB_E_IO;
    memcpy(f->data,b,n);f->n=n;f->exists=true;return WB_OK;}
int sceIoRemove(const char*p){int i=slot(p);if(fail_remove&&i==2)return -1;
    if(!files[i].exists)return NOENT;
    files[i].exists=false;return 0;}
int sceIoGetstat(const char*p,SceIoStat*st){assert(st);int i=slot(p);if(fail_stat&&i==0)return -1;
    return files[i].exists?0:NOENT;}
int sceAppUtilSaveDataDataSave(SceAppUtilSaveDataFileSlot*s,SceAppUtilSaveDataFile*f,unsigned n,SceAppUtilSaveDataMountPoint*m,SceSize*r){
    assert(!s&&!m&&r&&n==1&&!strcmp(f->filePath,R1_NAME)&&f->bufSize==sizeof(r1_local));
    return fail_save?-1:wq_save(R1_LOCAL_PATH,f->buf,f->bufSize);}
int sceRtcGetCurrentTick(SceRtcTick*x){x->tick=wall;return wall?0:-1;}
int sceKernelGetRandomNumber(void*d,SceSize n){assert(n==16);memset(d,0x6A,n);return 0;}
static int wq_sealed_receipt(const char*p,const char*q,char*out){assert(!strcmp(p,WB_PENDING_PATH)&&!strcmp(q,WBQ_SEAL));
    if(!stage[0])return WB_E_STATE;
    strcpy(out,stage);return WB_OK;}
static int wq_installed_receipt(const char*p,const char*v,char*out){assert(!strcmp(p,"ux0:app/INAP00018")&&!strcmp(v,active_version));
    if(!installed[0])return WB_E_IO;
    strcpy(out,installed);return WB_OK;}
int wb_out_printf(wb_out*out,const char*fmt,...){(void)out;va_list ap;va_start(ap,fmt);vsnprintf(output,sizeof output,fmt,ap);va_end(ap);return 0;}
static const char *const oldrun="ABABABABABABABAB",*const newrun="CDCDCDCDCDCDCDCD";
static void reset(void){memset(files,0,sizeof files);memset(&r1_completed,0,sizeof r1_completed);r1_bound=r1_source_live=false;
    r1_last_rtc=r1_start_ms=0;wall=UINT64_C(123456789);mono=88;healthy_stage=1;
    fail_save=fail_readback=fail_stat=fail_export=fail_remove=false;
    active_version="01.33";a.pin=stored_host=host;a.user_pin=own;a.run_hex=oldrun;
    assert(strlen(own)==64&&strlen(host)==64);
    snprintf(stage,sizeof stage,"WBQ2 01.34 %064x 70123\n",13);strcpy(installed,stage);}
static void expect(const char*state){char q[64];snprintf(q,sizeof q,"r1 state=%s ",state);assert(!r1_status(NULL));assert(!strncmp(output,q,strlen(q)));}
static void arm(void){r1_local l;assert(r1_issue_local(stage)==WB_OK);expect("authorized");assert(r1_get(R1_LOCAL_PATH,&l,sizeof l));
    strcpy(nonce,l.t.nonce); assert(strstr(output,nonce)&&strstr(output,"target=01.34")&&strstr(output,oldrun));}
static void ship(void){arm();assert(r1_apply(nonce,false)==WB_OK);assert(!files[1].exists);assert(r1_apply(nonce,true)==WB_OK);
    assert(files[1].exists&&!files[2].exists);expect("dispatched");assert(r1_apply(nonce,true)!=WB_OK);}
static void boot_env(void){active_version="01.34";a.run_hex=newrun;r1_source_live=false;r1_bound=false;wall++;files[2]=files[1];}
static void tomb_or_error(void){r1_local s;assert(r1_get(R1_LOCAL_PATH,&s,sizeof s)&&s.phase==0);}
int main(void){int cases=0;wb_r1_ticket t={0};
    reset();expect("none");assert(r1_issue_local("not-reviewed")!=WB_OK);++cases;
    healthy_stage=0;assert(r1_issue_local(stage)!=WB_OK);++cases;
    reset();fail_save=true;assert(r1_issue_local(stage)!=WB_OK);++cases;
    reset();arm();assert(r1_apply("BAD",false)!=WB_OK);++cases;
    stage[20]='b';assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();healthy_stage=0;assert(r1_apply(nonce,true)!=WB_OK);++cases;
    reset();arm();a.pin=own;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();a.user_pin=host;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();a.run_hex=newrun;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();fail_export=true;assert(r1_apply(nonce,true)!=WB_OK);tomb_or_error();++cases;
    reset();arm();assert(r1_revoke()==WB_OK);assert(r1_apply(nonce,true)!=WB_OK);++cases;
    reset();arm();wall+=WB_R1_TTL;expect("expired");wall-=WB_R1_TTL;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();wall++;expect("authorized");--wall;expect("expired");++wall;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();arm();mono+=WB_R1_TTL/1000u;assert(r1_apply(nonce,false)!=WB_OK);++cases;
    reset();ship();boot_env();assert(r1_boot(&t));assert(!files[1].exists&&!files[2].exists);tomb_or_error();
    expect("none");r1_completed=t;r1_bound=true;expect("returned");assert(strstr(output,newrun)&&strstr(output,oldrun));++cases;
    files[2].exists=true;assert(!r1_boot(&t));assert(!files[2].exists);++cases;
    for(int mode=0;mode<14;mode++){reset();ship();boot_env();
        switch(mode){case 0:files[2].exists=false;break;case 1:files[2].n--;break;case 2:files[2].data[0]^=1;break;
          case 3:active_version="01.35";break;case 4:stored_host=own;break;case 5:a.user_pin=host;break;
          case 6:a.run_hex=oldrun;break;case 7:installed[12]='f';break;case 8:stored_host=NULL;break;
          case 9:wall+=WB_R1_TTL;break;case 10:installed[0]=0;break;case 11:files[0].exists=false;break;
          case 12:fail_stat=true;break;case 13:fail_save=true;break;}
        assert(!r1_boot(&t));assert(!files[1].exists&&!files[2].exists);fail_stat=fail_save=false;assert(!r1_boot(&t));++cases;
    }
    reset();arm();boot_env();assert(!r1_boot(&t));tomb_or_error();++cases;
    reset();ship();boot_env();fail_readback=true;assert(!r1_boot(&t));assert(!files[2].exists);++cases;
    reset();ship();boot_env();fail_remove=true;assert(!r1_boot(&t));tomb_or_error();++cases;
    printf("PASS %d R1 core cases: actual savedata/dispatch/return/status functions, in-memory storage and time, no network\n",cases);
    return 0;
}
