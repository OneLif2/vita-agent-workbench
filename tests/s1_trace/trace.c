/* Native fixture; neutral source of I/O fault parameters, never MOUNT/SSH/Vita.
 * Harness chdirs to an isolated temp tree, no actual native promoter/device operations. */
#include <assert.h>
#include <errno.h>
#include "wbq_io.h"
#include "adapter.inc"
#define RAW ((int)UINT32_C(0x80010005))
#define NOENT ((int)UINT32_C(0x80010002))
static const char *fop,*fpath;
static int live, hits, handoffs;
static int legacy_mode_report=-1;
static int mode_model, secondary;
static const char *scenario;
#define MODEL_EINVAL ((int)UINT32_C(0x80010016))
static char opened[512][WQPATH], opened_dirs[32][WQPATH];
static int match(const char *op,const char *p){if(!live || strcmp(fop,op))return 0;
 size_t n=strlen(fpath);
 /* Match exact receipt or its temporary sibling, never arbitrary paths. */
 if(strcmp(p,fpath) && (strncmp(p,fpath,n) || p[n]!='.'))return 0;
 hits++;return 1;}
static int err(int rc){return rc>=0?rc:errno==ENOENT?NOENT:RAW;}
int sceIoMkdir(const char*p,SceMode m){if(mode_model==2 && !strcmp(p,WBQ_FINAL)){legacy_mode_report=(int)m;if((m&7)!=7){hits++;return MODEL_EINVAL;}} if(match("mkdir",p))return RAW;return err(raw_sceIoMkdir(p,m));}
int sceIoRmdir(const char*p){return err(raw_sceIoRmdir(p));}
int sceIoRemove(const char*p){if(match("remove",p))return RAW;return err(raw_sceIoRemove(p));}
int sceIoGetstat(const char*p,SceIoStat*s){if(match("stat",p))return RAW;return err(raw_sceIoGetstat(p,s));}
int sceIoDopen(const char*p){if(match("dopen",p))return RAW;int n=raw_sceIoDopen(p);if(n>=0){assert(n<32);strcpy(opened_dirs[n],p);}return err(n);}
int sceIoDread(SceUID i,SceIoDirent*e){if(match("dread",opened_dirs[i]))return RAW;return raw_sceIoDread(i,e);}
int sceIoDclose(SceUID i){int rc=raw_sceIoDclose(i);return match("dclose",opened_dirs[i])?RAW:rc;}
int sceIoOpen(const char*p,int f,SceMode m){
 if(mode_model==3 && (f&SCE_O_CREAT) && strstr(p,"/s1cal-") && (m&6)!=6)return MODEL_EINVAL;
 if(mode_model==1 && (f&SCE_O_CREAT) && !strcmp(p,WBQ_SEAL)){
  legacy_mode_report=(int)m;if((m&6)!=6){hits++;return MODEL_EINVAL;}}
 if(match(f&SCE_O_WRONLY?"open-write":"open-read",p))return RAW;
 int n=raw_sceIoOpen(p,f,m);if(n>=0){assert(n<512);snprintf(opened[n],WQPATH,"%s",p);}return err(n);}
int sceIoRead(SceUID i,void*p,SceSize n){if(match("read",opened[i]))return RAW;
 int out=raw_sceIoRead(i,p,n);if(out>0 && match("readback-different",opened[i]))((unsigned char *)p)[0]^=1;
 return out;}
int sceIoWrite(SceUID i,const void*p,SceSize n){if(match("write",opened[i]))return RAW;
 if(match("zero-write",opened[i]))return 0;
 if(match("short-write",opened[i]) && n>3)n=3;
 return raw_sceIoWrite(i,p,n);}
int sceIoClose(SceUID i){int rc=raw_sceIoClose(i);if(!strcmp(scenario,"double-error") && live && !strcmp(opened[i],fpath)) {secondary++;return (int)UINT32_C(0x80010009);}
 return match("close",opened[i])?RAW:rc;}
int sceIoSyncByFd(SceUID i,int f){if(match("sync",opened[i]))return RAW;return raw_sceIoSyncByFd(i,f);}
SceOff sceIoLseek(SceUID i,SceOff off,int m){return raw_sceIoLseek(i,off,m);}
int sceIoRename(const char*a,const char*b){if(match("rename",b))return RAW;char dst[WQPATH];strcpy(dst,native(b));return err(rename(native(a),dst));}
int sceIoSync(const char*p,unsigned f){(void)f;return match("sync-volume",p)?RAW:0;}
static int consumer(const char *p,void*ctx){(void)ctx;assert(!strcmp(p,WBQ_FINAL));handoffs++;return 0;}
#include "production.inc"
int main(int argc,char**argv){
 if(argc!=4)return 2;const char*mode=argv[1];scenario=mode;fop=argv[2];fpath=argv[3];
 char receipt[WBQ_CAP]={0},result[WBQ_CAP]={0};wbq_manifest m={0};
 assert(wq_measure(WB_STAGE_DIR,NULL,&m)==WB_OK && wbq_format(&m,"01.33",receipt)==WB_OK);
 if(!strcmp(mode,"digest"))assert(!wq_save(WB_STAGE_DIR "/eboot.bin","different",9));
 if(!strcmp(mode,"missing"))assert(!sceIoRemove(WB_STAGE_DIR "/eboot.bin"));
 if(!strcmp(mode,"extra"))assert(!wq_save(WB_STAGE_DIR "/unapproved","x",1));
 mode_model=!strcmp(mode,"model-file")?1:!strcmp(mode,"model-dir")?2:0;
 if(!strcmp(mode,"mode-calibration"))mode_model=3;
 if(!strcmp(mode,"calibration-collision")){
  assert(!wq_mkdir(WBQ_STORE));assert(!wq_save(WBQ_STORE "/s1cal-owner.bin","preserve",8));}
 live=1;
 int rc=production_seal(receipt);live=0;
 printf("case=%s/%s injected=%d rc=%d",mode,fop,hits,rc);
#if HAS_TRACE
 printf(" phase=%s op=%s path=%s raw=%08X has_raw=%d",wq_last.phase?wq_last.phase:"-",wq_last.op?wq_last.op:"-",wq_last.path[0]?wq_last.path:"-",(unsigned)wq_last.raw,(int)wq_last.has_raw);
#else
 printf(" phase=- op=- path=- raw=00000000 has_raw=0");
#endif
#if HAS_TRACE && WBQ_LEGACY_PROBE
 if(!strcmp(mode,"mode-calibration")){assert(!rc && !strcmp(wq_trials[0].op,"open-write") && wq_trials[0].raw==MODEL_EINVAL);assert(!strcmp(wq_trials[1].op,"pass") && !wq_trials[1].raw);}
 if(!strcmp(mode,"calibration-collision")){size_t n=0;char save[9]={0};assert(!rc && !strcmp(wq_trials[0].op,"exists") && !strcmp(wq_trials[1].op,"pass") && !wq_read(WBQ_STORE "/s1cal-owner.bin",save,sizeof save,&n) && n==8 && !memcmp(save,"preserve",8));}
 if(!strcmp(mode,"mode-calibration") || !strcmp(mode,"calibration-collision"))printf(" trial0600=%s/%08X trial0606=%s/%08X",wq_trials[0].op,(unsigned)wq_trials[0].raw,wq_trials[1].op,(unsigned)wq_trials[1].raw);
#endif
 if(!rc && !strcmp(mode,"legacy"))assert(!wq_save(WB_PENDING_PATH,"WBQ1 01.33\n",11));
 if(!rc && !strcmp(mode,"private-mismatch"))assert(!wq_save(WBQ_SEAL,"different",9));
 if(!rc && !strcmp(mode,"late-change"))assert(!wq_save(WB_STAGE_DIR "/workbench_payload.suprx","different",9));
 int paired=!wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,result);
 int final=wq_final(WB_PENDING_PATH,WBQ_SEAL,WB_STAGE_DIR,WBQ_FINAL,"01.32",consumer,NULL);
 printf(" pair=%d handoff=%d final_rc=%d create_mode=%04o total_injections=%d secondary=%d\n",paired,handoffs,final,legacy_mode_report<0?0:(unsigned)legacy_mode_report,hits,secondary);
 return 0;
}
