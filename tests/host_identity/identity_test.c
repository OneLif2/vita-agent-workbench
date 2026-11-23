/* Production identity code and actual native libssh/mbedTLS. Storage is a
 * controlled in-memory model, never a live Vita, console or owner's keys. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <psp2/apputil.h>
#include "wb_host_identity.h"
#define DIR "ur0:/data/INAP00018-host-id"
#define LK DIR "/host.private"
#define LS DIR ".sha256"
#define CLAIM "savedata0:/wb-hi-claim.bin"
#define KEY "savedata0:/wb-hi-key.bin"
#define SEAL "savedata0:/wb-hi-seal.bin"
#define NOSUCH ((int)0x80010002U)
#define IOERR ((int)0x80010005U)
typedef struct { char name[128]; unsigned mode; size_t n; unsigned char b[5200]; } Node;
typedef struct { int i,used; size_t pos; } File;
static Node nodes[20],saved[20];
static File files[16];
static unsigned op, fail_at, writes, save_calls, split_reads, zero_reads, partial_batch, counts;
static int fault(void){return ++op==fail_at;}
static int at(const char*p){for(int i=0;i<20;i++)if(nodes[i].mode&&!strcmp(p,nodes[i].name))return i;return -1;}
static int make(const char*p,unsigned mode){
    assert(strlen(p)<sizeof nodes[0].name && at(p)<0);
    for(int i=0;i<20;i++)if(!nodes[i].mode){strcpy(nodes[i].name,p);nodes[i].mode=mode;nodes[i].n=0;return i;}
    abort();
}
static void put(const char*p,const void*b,size_t n){
    assert(n && n<=sizeof nodes[0].b); int i=at(p); if(i<0)i=make(p,SCE_S_IFREG);
    assert(nodes[i].mode==SCE_S_IFREG); memcpy(nodes[i].b,b,n);nodes[i].n=n;
}
#ifndef WB_LEGACY_BASELINE
static void forget(const char*p){assert(at(p)>=0);nodes[at(p)].mode=0;}
#endif
/* Fail if any new code writes through raw I/O or anywhere outside title saves. */
int sceIoMkdir(const char*p,SceMode m){
#ifdef WB_LEGACY_BASELINE
    assert(!strcmp(p,DIR)&&m==0700);return (int)0x8001000DU;
#else
    (void)p;(void)m;abort();
#endif
}
int sceIoRename(const char*a,const char*b){(void)a;(void)b;abort();}
int sceIoSync(const char*p,unsigned f){(void)p;(void)f;abort();}
int sceIoSyncByFd(int d,int f){(void)d;(void)f;abort();}
int sceIoWrite(int d,const void*b,unsigned n){(void)d;(void)b;(void)n;abort();}
int sceIoGetstat(const char*p,SceIoStat*s){if(fault())return IOERR;int i=at(p);if(i<0)return NOSUCH;memset(s,0,sizeof *s);s->st_size=nodes[i].n;s->st_mode=nodes[i].mode;return 0;}
int sceIoOpen(const char*p,int mode,SceMode perm){assert(mode==SCE_O_RDONLY && !perm);if(fault())return IOERR;int i=at(p);if(i<0)return NOSUCH;
    if(nodes[i].mode!=SCE_S_IFREG)return IOERR;
    for(int j=1;j<16;j++)if(!files[j].used){files[j]=(File){i,1,0};return j;}
    abort();}
int sceIoClose(int fd){assert(fd>0&&fd<16&&files[fd].used);files[fd].used=0;return fault()?IOERR:0;}
int sceIoRead(int fd,void*b,unsigned n){assert(fd>0&&fd<16&&files[fd].used);if(fault())return IOERR;
    File*f=&files[fd];Node*s=&nodes[f->i];size_t total=n;
    if(total>s->n-f->pos)total=s->n-f->pos;
    if(zero_reads&&total)return 0;
    if(split_reads&&total>11)total=11;
    memcpy(b,s->b+f->pos,total);f->pos+=total;return (int)total;
}
int sceAppUtilSaveDataDataSave(SceAppUtilSaveDataFileSlot*slot,SceAppUtilSaveDataFile*e,unsigned n,SceAppUtilSaveDataMountPoint*mount,SceSize*kb){
    assert(!slot&&!mount&&kb&&e&&(n==1||n==2));++save_calls;
    if(fault())return IOERR;
    *kb=0;
    for(unsigned i=0;i<n;i++){
        const char *expected=n==1?"wb-hi-claim.bin":i==0?"wb-hi-key.bin":"wb-hi-seal.bin";
        assert(!strcmp(e[i].filePath,expected)&&e[i].buf&&e[i].bufSize&&e[i].bufSize<=4096&&e[i].mode==0&&e[i].offset==0);
        char full[128];assert(snprintf(full,sizeof full,"savedata0:/%s",expected)>0);
        assert(at(full)<0);put(full,e[i].buf,e[i].bufSize);++writes;
        if(n==2&&partial_batch==i+1)return IOERR;
    }return 0;
}
static void fresh(void){memset(nodes,0,sizeof nodes);memset(files,0,sizeof files);
    writes=op=fail_at=save_calls=split_reads=zero_reads=partial_batch=0;make("ur0:/data",SCE_S_IFDIR);make("savedata0:",SCE_S_IFDIR);make("savedata0:/",SCE_S_IFDIR);}
#ifdef WB_LEGACY_BASELINE
int main(void){
    const char *why=NULL;ssh_key k=NULL;
    assert(ssh_init()==SSH_OK);fresh();(void)saved;(void)counts;
    assert(wb_host_identity_acquire_ex(&k,&why)==SSH_ERROR&&!k&&!writes&&!save_calls);
    assert(why&&!strcmp(why,"HOST ID ENROLL STORAGE"));
    printf("BASELINE: ur0 data readable, ur0 mkdir denied -> %s; no identity, no listener; writes=%u\n",why,writes);
    ssh_finalize();return 0;
}
#else
static void restore(void){fresh();memcpy(nodes,saved,sizeof saved);}
static int run(unsigned char out[32],int allow){
    const char *why=NULL;ssh_key k=NULL;int rc=wb_host_identity_get_ex(&k,&why,allow);
    if(rc==SSH_OK){unsigned char*h=NULL;size_t n=0;assert(k&&ssh_get_publickey_hash(k,SSH_PUBLICKEY_HASH_SHA256,&h,&n)==SSH_OK&&n==32);memcpy(out,h,32);ssh_clean_pubkey_hash(&h);ssh_key_free(k);}
    else assert(!k&&why&&*why);
    for(int i=0;i<16;i++)assert(!files[i].used);
    return rc;
}
static void pass(const char *tag){printf("PASS: %s\n",tag);++counts;}
static void refuse(const char*tag){unsigned char a[32];unsigned w=writes,s=save_calls;
    assert(run(a,1)!=SSH_OK&&writes==w&&save_calls==s);pass(tag);}
static void copy_legacy(const Node*k,const Node*s){make(DIR,SCE_S_IFDIR);put(LK,k->b,k->n);put(LS,s->b,s->n);}
int main(void){unsigned char a[32],b[32];
    assert(ssh_init()==SSH_OK);
    fresh();assert(run(a,0)!=SSH_OK&&!writes&&!save_calls);pass("unauthorized first use: no fresh identity and no write");
    fresh();assert(run(a,1)==SSH_OK&&save_calls==2&&writes==3&&at(CLAIM)>=0&&at(KEY)>=0&&at(SEAL)>=0);
    unsigned enroll_ops=op;memcpy(saved,nodes,sizeof nodes);pass("first authorized boot writes claim then separate key+seal via title save API");
    restore();assert(run(b,0)==SSH_OK&&!memcmp(a,b,32)&&!writes&&!save_calls);
    unsigned load_ops=op;pass("cold restart reads persisted identity without any enrollment/write");
    restore();split_reads=1;assert(run(b,1)==SSH_OK&&!memcmp(a,b,32)&&!writes);pass("positive short read handling");
    restore();zero_reads=1;refuse("unexpected zero-byte read");
    restore();forget(KEY);refuse("missing savedata key");
    restore();forget(SEAL);refuse("missing savedata seal");
    restore();forget(CLAIM);refuse("missing savedata claim");
    restore();nodes[at(CLAIM)].b[0]^=0x01;refuse("wrong claim");
    restore();nodes[at(KEY)].n/=2;refuse("truncated private record");
    restore();nodes[at(KEY)].n=0;refuse("empty private record");
    restore();nodes[at(KEY)].n=5100;refuse("oversize private record");
    restore();nodes[at(KEY)].mode=SCE_S_IFDIR;refuse("directory in place of key");
    restore();nodes[at(KEY)].b[nodes[at(KEY)].n-1]^=1;refuse("single trailing byte changed");
    restore();nodes[at(SEAL)].n=31;refuse("truncated public seal");
    restore();nodes[at(SEAL)].b[0]^=1;refuse("mismatched SHA of public key");
    fresh();assert(run(b,1)==SSH_OK&&memcmp(a,b,32));Node other=nodes[at(KEY)];restore();nodes[at(KEY)]=other;refuse("substitution of validly framed independent key");
    restore();Node k=nodes[at(KEY)],s=nodes[at(SEAL)];fresh();copy_legacy(&k,&s);
    assert(run(b,0)==SSH_OK&&!memcmp(a,b,32)&&!writes&&!save_calls);pass("prior complete legacy identity retained in place, zero saves");
    fresh();make(DIR,SCE_S_IFDIR);refuse("pre-existing empty legacy directory, no fallback");
    fresh();put(LS,s.b,s.n);refuse("legacy seal alone, no fallback");
    fresh();copy_legacy(&k,&s);nodes[at(LK)].b[0]^=1;refuse("legacy key damaged, no fallback");
    restore();make(DIR,SCE_S_IFDIR);refuse("savedata plus partial legacy, refuse ambiguous origins");
    restore();copy_legacy(&k,&s);refuse("both savedata and complete legacy identities, refuse ambiguous origins");
    fresh();partial_batch=1;assert(run(b,1)!=SSH_OK&&at(CLAIM)>=0&&at(KEY)>=0&&at(SEAL)<0);
    partial_batch=0;refuse("simulated partially committed AppUtil batch, no automatic regeneration");
    for(unsigned f=1;f<=load_ops;f++){restore();fail_at=f;assert(run(b,0)!=SSH_OK&&!writes&&!save_calls);}
    printf("  %u I/O positions\n",load_ops);pass("all enrolled-read I/O faults fail closed");
    for(unsigned f=1;f<=enroll_ops;f++){
        fresh();fail_at=f;int rc=run(b,1);assert(rc!=SSH_OK);
        if(at(CLAIM)>=0&&(at(KEY)<0||at(SEAL)<0)){fail_at=0;unsigned w=writes,saves=save_calls;assert(run(b,1)!=SSH_OK&&writes==w&&save_calls==saves);}
    }
    printf("  %u I/O positions\n",enroll_ops);pass("all first-boot I/O faults reject session, no regeneration from partial state");
    ssh_finalize();printf("PASS %u host-identity scenarios; simulated Vita storage only\n",counts);return 0;
}

#endif /* WB_LEGACY_BASELINE */
