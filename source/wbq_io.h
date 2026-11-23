#ifndef WBQ_IO_H
#define WBQ_IO_H
#include "wb_queued.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/io/dirent.h>
#include <stdlib.h>
#define WQPATH 256

/* Single-threaded core commands / standalone updater. Keep only first failure:
 * later close, logging and cleanup must not replace the actual syscall result. */
typedef struct {const char *phase,*op;char path[WQPATH];int raw,code,has_raw;} wq_diag;
static wq_diag wq_last;
static const char *wq_phase;
static inline void wq_begin(const char *phase){
 memset(&wq_last,0,sizeof wq_last);wq_phase=phase;
}
static inline int wq_note(wq_diag *d,const char *op,const char *path,int code,int raw,int native){
 if(!d->op){d->phase=wq_phase?wq_phase:"io";d->op=op;d->code=code;d->raw=raw;d->has_raw=native;
   snprintf(d->path,sizeof d->path,"%s",path?path:"-");}
 return code;
}
static inline int wq_native(const char *op,const char *p,int rc,int raw){return wq_note(&wq_last,op,p,rc,raw,1);}
static inline int wq_bad(const char *op,const char *p,int rc){return wq_note(&wq_last,op,p,rc,0,0);}
static inline int wq_diag_format(char *dst,size_t cap,const wq_diag *d){
 if(!d->op)return 0;
 if(d->has_raw)return snprintf(dst,cap,"phase=%s op=%s path=%s native=0x%08X rc=%d",d->phase,d->op,d->path,(unsigned)d->raw,d->code);
 return snprintf(dst,cap,"phase=%s op=%s path=%s native=none rc=%d",d->phase,d->op,d->path,d->code);
}
static inline int wq_path(char out[WQPATH],const char *root,const char *rel){
 int n=snprintf(out,WQPATH,"%s/%s",root,rel);return n>0 && n<WQPATH?WB_OK:wq_bad("path-limit",root,WB_E_LIMIT);
}
enum {WQ_FILE_MODE=0606, WQ_DIR_MODE=0707};
static inline int wq_mkdir(const char *p){
 int first=sceIoMkdir(p,WQ_DIR_MODE);if(first>=0)return WB_OK;
 SceIoStat st={0};int z=sceIoGetstat(p,&st);if(z>=0 && SCE_S_ISDIR(st.st_mode))return WB_OK;
 return wq_native("mkdir",p,WB_E_IO,first);
}
static inline int wq_write_at(int fd,const char *path,const void *buf,size_t n){
 const unsigned char *s=buf;while(n){int z=sceIoWrite(fd,s,n);
  if(z<=0 || (size_t)z>n)return wq_native("write",path,WB_E_IO,z);
  s+=z;n-=(size_t)z;}return WB_OK;
}
static inline int wq_write(int fd,const void *buf,size_t n){return wq_write_at(fd,NULL,buf,n);}
static inline int wq_close(int fd,const char *p,int rc){
 int raw=sceIoClose(fd);if(raw<0 && !rc)return wq_native("close",p,WB_E_IO,raw);return rc;
}
static inline int wq_sync(int fd,const char *p,int rc){
 if(!rc){int z=sceIoSyncByFd(fd,0);if(z<0)rc=wq_native("sync",p,WB_E_IO,z);}return rc;
}
/* SceIoAccessMode differs from POSIX: low bits are SYSTEM, not "other".
 * Full-permission SELF must supply system RW. No group bits or access fallback. */
static inline int wq_open_write(const char *p){
 int z=sceIoOpen(p,SCE_O_CREAT|SCE_O_TRUNC|SCE_O_WRONLY,WQ_FILE_MODE);
 if(z<0)(void)wq_native("open-write",p,WB_E_IO,z);
 return z;
}
static inline int wq_save(const char *p,const void *data,size_t n){
 int fd=wq_open_write(p);if(fd<0)return WB_E_IO;
 return wq_close(fd,p,wq_sync(fd,p,wq_write_at(fd,p,data,n)));
}
/* Bounded read to EOF with independent trailing-byte and native-error handling. */
static inline int wq_read(const char *p,void *p0,size_t cap,size_t *used){
 unsigned char *b=p0,extra;*used=0;int fd=sceIoOpen(p,SCE_O_RDONLY,0);
 if(fd<0)return wq_native("open-read",p,WB_E_IO,fd);
 size_t n=0;int rc=WB_OK;while(n<cap){int k=sceIoRead(fd,b+n,cap-n);
  if(k<0 || (size_t)k>cap-n){rc=wq_native("read",p,WB_E_IO,k);break;}
  if(!k)break;
  n+=(size_t)k;
 }
 if(!rc && n==cap){int k=sceIoRead(fd,&extra,1);
  if(k<0)rc=wq_native("read",p,WB_E_IO,k);
  else if(k>0)rc=wq_bad("size-limit",p,WB_E_LIMIT);}
 *used=n;return wq_close(fd,p,rc);
}
static inline int wq_identity_file(const char *path,char ver[6]){
 uint8_t *p=malloc(65536);if(!p)return wq_bad("allocate",path,WB_E_NOMEM);size_t n=0;
 int rc=wq_read(path,p,65536,&n);
 if(!rc && (rc=wbq_identity(p,n,ver))!=WB_OK)(void)wq_bad("identity",path,rc);
 free(p);return rc;
}
static inline int wq_shape(const char *root){
 static const char *const dirs[3]={"","sce_sys","sce_sys/package"};
 static const char *const names[3][3]={{"eboot.bin","sce_sys","workbench_payload.suprx"},{"param.sfo","package",NULL},{"head.bin",NULL,NULL}};
 for(unsigned l=0;l<3;l++){
  char p[WQPATH];if(l && wq_path(p,root,dirs[l]))return WB_E_LIMIT;const char *dir=l?p:root;
  int fd=sceIoDopen(dir);if(fd<0)return wq_native("dopen",dir,WB_E_STAGE,fd);
  unsigned mask=0,need=l==0?7u:l==1?3u:1u;int rc=WB_OK;
  for(;;){SceIoDirent e;memset(&e,0,sizeof e);int k=sceIoDread(fd,&e);
   if(k<0){rc=wq_native("dread",dir,WB_E_IO,k);break;}if(!k)break;
   if(!memchr(e.d_name,0,sizeof e.d_name)){rc=wq_bad("name",dir,WB_E_STAGE);break;}
   if(!strcmp(e.d_name,".") || !strcmp(e.d_name,".."))continue;
   unsigned j=0;while(j<3 && names[l][j] && strcmp(e.d_name,names[l][j]))j++;
   if(j==3 || !names[l][j] || (mask&(1u<<j)) ||
      ((j==1 && l<2)?!SCE_S_ISDIR(e.d_stat.st_mode):!SCE_S_ISREG(e.d_stat.st_mode))){rc=wq_bad("shape",dir,WB_E_STAGE);break;}
   mask|=1u<<j;
  }
  int c=sceIoDclose(fd);if(c<0 && !rc)rc=wq_native("dclose",dir,WB_E_IO,c);
  if(rc)return rc;
  if(mask!=need)return wq_bad("missing-member",dir,WB_E_STAGE);
 }return WB_OK;
}
static inline int wq_dirs(const char *r){
 char p[WQPATH];int rc=wq_mkdir(r);
 if(!rc)rc=wq_path(p,r,"sce_sys");
 if(!rc)rc=wq_mkdir(p);
 if(!rc)rc=wq_path(p,r,"sce_sys/package");
 if(!rc)rc=wq_mkdir(p);
 return rc;
}
/* Cleanup never walks an unknown directory or deletes unknown files. */
static inline void wq_cleanup(const char *r){
 char p[WQPATH];for(unsigned i=0;i<4;i++)if(!wq_path(p,r,wbq_names[i]))(void)sceIoRemove(p);
 if(!wq_path(p,r,"sce_sys/package"))(void)sceIoRmdir(p);
 if(!wq_path(p,r,"sce_sys"))(void)sceIoRmdir(p);
 (void)sceIoRmdir(r);
}
static inline int wq_measure_members(const char *root,const char *copy,wbq_manifest *m){
 memset(m,0,sizeof *m);
 for(unsigned i=0;i<4;i++){
  char src[WQPATH],dst[WQPATH];if(wq_path(src,root,wbq_names[i]))return WB_E_LIMIT;
  int in=sceIoOpen(src,SCE_O_RDONLY,0),out=-1,rc=WB_OK;if(in<0)return wq_native("open-read",src,WB_E_IO,in);
  if(copy){rc=wq_path(dst,copy,wbq_names[i]);if(!rc && (out=wq_open_write(dst))<0)rc=WB_E_IO;}
  unsigned char b[4096];wb_sha256 h;wb_sha256_init(&h);uint64_t n=0;
  while(!rc){int k=sceIoRead(in,b,sizeof b);
   if(k<0 || (size_t)k>sizeof b){rc=wq_native("read",src,WB_E_IO,k);break;}
   if(!k)break;
   n+=(unsigned)k;if(n>WBQ_FILE_MAX){rc=wq_bad("size-limit",src,WB_E_LIMIT);break;}
   if(out>=0)rc=wq_write_at(out,dst,b,(size_t)k);
   if(!rc)wb_sha256_update(&h,b,(size_t)k);
  }
  rc=wq_close(in,src,rc);if(out>=0)rc=wq_close(out,dst,wq_sync(out,dst,rc));
  if(rc)return rc;
  if(!n)return wq_bad("empty-member",src,WB_E_FORMAT);
  wb_sha256_final(&h,m->hash[i]);m->size[i]=n;
 }
 return WB_OK;
}
static inline int wq_measure(const char *root,const char *copy,wbq_manifest *m){
 int rc=wq_shape(root);if(!rc)rc=wq_measure_members(root,copy,m);
 return rc?rc:wq_shape(root);
}
static inline int wq_installed_receipt(const char *root,const char *version,char out[WBQ_CAP]){
 char path[WQPATH],installed[6];wbq_manifest m;out[0]=0;
 if(wq_path(path,root,"sce_sys/param.sfo"))return WB_E_LIMIT;
 int rc=wq_identity_file(path,installed);if(rc)return rc;
 if(!wbq_version_ok(version)||strcmp(installed,version))return wq_bad("version",path,WB_E_VERSION);
 rc=wq_measure_members(root,NULL,&m);return rc?rc:wbq_format(&m,installed,out);
}
static inline int wq_sealed_receipt(const char *pub,const char *priv,char out[WBQ_CAP]){
 char b[WBQ_CAP];size_t pn=0,sn=0;int rc=wq_read(pub,out,WBQ_CAP-1,&pn);
 if(rc)return WB_E_STATE;
 if(pn<78 || memcmp(out,WBQ_PREFIX,5) || memchr(out,0,pn))return wq_bad("receipt-format",pub,WB_E_STATE);
 rc=wq_read(priv,b,sizeof b,&sn);if(rc)return WB_E_STATE;
 if(pn!=sn || memcmp(out,b,pn))return wq_bad("receipt-mismatch",priv,WB_E_STATE);
 out[pn]=0;return WB_OK;
}
static inline int wq_check_tree(const char *tree,const char *copy,const char *receipt,const char *running){
 char path[WQPATH],ver[6],expected[WBQ_CAP];wbq_manifest m;
 if(wq_path(path,tree,"sce_sys/param.sfo"))return WB_E_LIMIT;
 int rc=wq_identity_file(path,ver);if(rc)return rc;
 if(!wbq_version_ok(running) || strcmp(ver,running)<=0)return wq_bad("not-newer",path,WB_E_VERSION);
 rc=wq_measure(tree,copy,&m);if(rc)return rc;
 rc=wbq_format(&m,ver,expected);if(rc)return wq_bad("manifest-format",tree,rc);
 return strcmp(expected,receipt)?wq_bad("manifest-mismatch",tree,WB_E_SHA):WB_OK;
}
static inline int wq_save_receipt(const char *p,const char *receipt,size_t n){
 int rc=wq_save(p,receipt,n);if(rc)return rc;
 char round[WBQ_CAP];size_t got=0;rc=wq_read(p,round,sizeof round,&got);
 if(!rc && (got!=n || memcmp(round,receipt,n)))rc=wq_bad("readback",p,WB_E_SHA);
 return rc;
}
/* Optional calibration build only. Harmless scratch files in the SAME
 * store, never the installed package, seal or queue. Refuse old scratch files:
 * no truncation or deletion of anything previously present. Serialized with
 * install; not available as a general filesystem or unauthenticated command. */
#ifndef WBQ_LEGACY_PROBE
#define WBQ_LEGACY_PROBE 0
#endif
#if WBQ_LEGACY_PROBE
typedef struct {unsigned mode;char path[WQPATH];const char *op;int raw;int cleanup;} wq_trial;
static wq_trial wq_trials[2];
static inline void wq_mode_trial(const char *store,const char *name,unsigned mode,wq_trial *t){
 static const char expected[]="WBQ2 mode probe, not a receipt\n";
 memset(t,0,sizeof *t);t->mode=mode;t->op="path";
 if(wq_path(t->path,store,name))return;
 SceIoStat st={0};int x=sceIoGetstat(t->path,&st);
 if((uint32_t)x!=UINT32_C(0x80010002)){t->op=x<0?"stat":"exists";t->raw=x;return;}
 int fd=sceIoOpen(t->path,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,mode);
 t->op="open-write";t->raw=fd;if(fd<0)return;
 size_t size=sizeof expected-1;
 x=sceIoWrite(fd,expected,size);t->op="write";t->raw=x;
 bool ok=x==(int)size;
 if(ok){x=sceIoSyncByFd(fd,0);t->op="sync";t->raw=x;ok=x>=0;}
 x=sceIoClose(fd);if(ok && x<0){t->op="close";t->raw=x;ok=false;}
 if(ok){
  char got[sizeof expected]={0};fd=sceIoOpen(t->path,SCE_O_RDONLY,0);
  if(fd<0){t->op="open-read";t->raw=fd;ok=false;}
  else{x=sceIoRead(fd,got,sizeof got);t->op="read";t->raw=x;ok=(size_t)x==size && !memcmp(got,expected,size);
   x=sceIoClose(fd);if(ok && x<0){t->op="close-read";t->raw=x;ok=false;}}
 }
 t->cleanup=sceIoRemove(t->path);
 if(ok){t->op=t->cleanup<0?"remove":"pass";t->raw=t->cleanup<0?t->cleanup:0;}
}
#endif
/* Public marker is the final publication point. A failed/partial/stale
 * marker alone never authorizes: the verifier requires the independent
 * private seal, exact stage hashes and strictly newer title version. */
static inline int wq_seal(const char *tree,const char *store,const char *seal,const char *pending,const char *receipt,const char *running){
 wq_begin("stage-check");
#if WBQ_LEGACY_PROBE
 memset(wq_trials,0,sizeof wq_trials);
#endif
 size_t n=strlen(receipt);int rc=wq_check_tree(tree,NULL,receipt,running);
 if(!rc && n>=WBQ_CAP)rc=wq_bad("receipt-limit",tree,WB_E_LIMIT);
 if(!rc){wq_phase="store";rc=wq_mkdir(store);}
#if WBQ_LEGACY_PROBE
 if(!rc){
  wq_mode_trial(store,"s1cal-owner.bin",0600,&wq_trials[0]);
  wq_mode_trial(store,"s1cal-system.bin",WQ_FILE_MODE,&wq_trials[1]);
 }
#endif
 if(!rc){wq_phase="private-receipt";rc=wq_save_receipt(seal,receipt,n);}
 if(!rc){wq_phase="public-receipt";rc=wq_save_receipt(pending,receipt,n);}
 if(rc){(void)sceIoRemove(pending);(void)sceIoRemove(seal);}
 return rc;
}
typedef int (*wq_consumer)(const char *path,void *ctx);
static inline int wq_final_receipt(const char *pub,const char *seal,const char *stage,const char *priv,
                           const char *running,wq_consumer consume,void *ctx,char *completed){
 if(completed)completed[0]=0;
 wq_begin("receipts");char receipt[WBQ_CAP];int rc=wq_sealed_receipt(pub,seal,receipt);
 if(rc)return rc;
 wq_phase="final-dir";wq_cleanup(priv);
 int raw=sceIoMkdir(priv,WQ_DIR_MODE);if(raw<0)return wq_native("mkdir",priv,WB_E_STAGE,raw);
 rc=wq_dirs(priv);
 if(!rc){wq_phase="stage-copy";rc=wq_check_tree(stage,priv,receipt,running);}
 if(!rc){wq_phase="final-verify";rc=wq_check_tree(priv,NULL,receipt,running);}
 if(!rc){wq_phase="promote";rc=consume(priv,ctx);if(rc)(void)wq_native("handoff",priv,rc,rc);}
 if(!rc && completed)memcpy(completed,receipt,strlen(receipt)+1);
 wq_cleanup(priv);
 return rc;
}
static inline int wq_final(const char *pub,const char *seal,const char *stage,const char *priv,
                           const char *running,wq_consumer consume,void *ctx){
 return wq_final_receipt(pub,seal,stage,priv,running,consume,ctx,NULL);
}
#endif
