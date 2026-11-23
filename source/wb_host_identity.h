#ifndef WB_HOST_IDENTITY_H
#define WB_HOST_IDENTITY_H
/* Private to wb_ssh.c. Fresh identities use *only* the application's standard
 * title save. Original ur0 identities are read-only. No remote file command or
 * payload may be given a path to either identity. This is not secure hardware.
 * Called once by the single-threaded startup path BEFORE opening the listener.
 * An in-progress/partial enrollment is never interpreted as a fresh install. */
#include <libssh/libssh.h>
#include "wb_sha256.h"
#include <psp2/apputil.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WB_HI_PARENT "ur0:/data"
#define WB_HI_DIR    WB_HI_PARENT "/INAP00018-host-id"
#define WB_HI_KEY    WB_HI_DIR "/host.private"
#define WB_HI_SEAL   WB_HI_DIR ".sha256"
#define WB_HI_CLAIM_NAME "wb-hi-claim.bin"
#define WB_HI_KEY_NAME   "wb-hi-key.bin"
#define WB_HI_SEAL_NAME  "wb-hi-seal.bin"
#define WB_HI_SAVE_CLAIM "savedata0:/" WB_HI_CLAIM_NAME
#define WB_HI_SAVE_KEY   "savedata0:/" WB_HI_KEY_NAME
#define WB_HI_SAVE_SEAL  "savedata0:/" WB_HI_SEAL_NAME
#define WB_HI_CLAIM "VITA WORKBENCH HOST ID CLAIM 1\n"
#define WB_HI_MAX 4096u
#define WB_HI_TAG "WBHK0001"
#define WB_HI_PREFIX 40u
enum { WB_HI_IO=-1, WB_HI_MISSING, WB_HI_DIRECTORY, WB_HI_REGULAR };
static void wb_hi_wipe(void *p,size_t n) {
    volatile unsigned char *v=p;
    while(n--) *v++=0;
}
/* Nonsecret operation and rc only; consumed synchronously in serialized startup.
 * Keep diagnostic short enough for the display as well as wb_ssh.error. */
static int wb_hi_error(const char **why,const char *op,int native) {
    static char msg[64];
    (void)snprintf(msg,sizeof msg,"ID %s %08X",op,(unsigned)(uint32_t)native);
    *why=msg;
    return SSH_ERROR;
}
static int wb_hi_kind(const char *path,size_t *size,const char *op,const char **why) {
    SceIoStat st={0};
    int rc=sceIoGetstat(path,&st);
    if ((uint32_t)rc==UINT32_C(0x80010002)) return WB_HI_MISSING;
    if(rc<0) { wb_hi_error(why,op,rc);return WB_HI_IO; }
    if(SCE_S_ISDIR(st.st_mode)) return WB_HI_DIRECTORY;
    if(!SCE_S_ISREG(st.st_mode) || (uint64_t)st.st_size>WB_HI_MAX) {
        *why="HOST ID TYPE OR SIZE";return WB_HI_IO;
    }
    if(size) *size=(size_t)st.st_size;
    return WB_HI_REGULAR;
}
static int wb_hi_read(const char *path,unsigned char *buf,size_t cap,size_t *got,
                      const char **why) {
    size_t n=0,off=0;
    *why="HOST ID READ TYPE";
    if(wb_hi_kind(path,&n,"READ STAT",why)!=WB_HI_REGULAR || !n || n>cap) return -1;
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);
    if(fd<0) return wb_hi_error(why,"OPEN",fd);
    int rc=0;
    while(off<n) {
        int k=sceIoRead(fd,buf+off,(SceSize)(n-off));
        if(k<0) {rc=wb_hi_error(why,"READ",k);break;}
        if(!k || (size_t)k>n-off) {*why="HOST ID SHORT READ";rc=-1;break;}
        off+=(size_t)k;
    }
    if(rc==0) {
        unsigned char extra=0;
        int k=sceIoRead(fd,&extra,1);
        wb_hi_wipe(&extra,1);
        if(k<0) rc=wb_hi_error(why,"READ EOF",k);
        else if(k!=0) {*why="HOST ID EXTRA DATA";rc=-1;}
    }
    int cr=sceIoClose(fd);
    if(cr<0 && rc==0) rc=wb_hi_error(why,"CLOSE",cr);
    if(rc==0) *got=n;
    return rc;
}
static int wb_hi_fingerprint(ssh_key key,unsigned char out[32]) {
    unsigned char *hash=NULL; size_t n=0;
    if(!key || !ssh_key_is_private(key) || ssh_key_type(key)!=SSH_KEYTYPE_ECDSA_P256) return -1;
    int rc=ssh_get_publickey_hash(key,SSH_PUBLICKEY_HASH_SHA256,&hash,&n);
    bool ok=rc==SSH_OK && hash && n==32;
    if(ok) memcpy(out,hash,32);
    ssh_clean_pubkey_hash(&hash);
    return ok?0:-1;
}
static void wb_hi_checksum(const unsigned char *b,size_t n,unsigned char out[32]) {
    wb_sha256 ctx;wb_sha256_init(&ctx);wb_sha256_update(&ctx,b,n);wb_sha256_final(&ctx,out);
    wb_hi_wipe(&ctx,sizeof ctx);
}
static int wb_hi_load(const char *key_path,const char *seal_path,ssh_key *out,
                      const unsigned char *new_expected,const char **why) {
    unsigned char expected[32],actual[32];
    unsigned char *record=NULL; size_t n=0;
    int rc=SSH_ERROR;ssh_key key=NULL;
    if(wb_hi_read(seal_path,expected,sizeof expected,&n,why)<0) return SSH_ERROR;
    *why="HOST ID SEAL INVALID";
    if(n!=32 || (new_expected && memcmp(expected,new_expected,32))) return SSH_ERROR;
    *why="HOST ID MEMORY"; record=calloc(1,WB_HI_MAX+1u);
    if(!record) return SSH_ERROR;
    if(wb_hi_read(key_path,record,WB_HI_MAX,&n,why)<0) goto done;
    *why="HOST ID KEY INVALID";
    if(n<=WB_HI_PREFIX || memcmp(record,WB_HI_TAG,8)) goto done;
    unsigned char *body=record+WB_HI_PREFIX;size_t len=n-WB_HI_PREFIX;
    wb_hi_checksum(body,len,actual);
    if(memcmp(actual,record+8,32) || memchr(body,0,len)) goto done;
    if(ssh_pki_import_privkey_base64((char *)body,"",NULL,NULL,&key)!=SSH_OK ||
       wb_hi_fingerprint(key,actual)<0 || memcmp(expected,actual,32)) goto done;
    *out=key;key=NULL;rc=SSH_OK;
done:
    wb_hi_wipe(record,WB_HI_MAX+1u);free(record);ssh_key_free(key);return rc;
}
static int wb_hi_claim_read(const char **why) {
    unsigned char saved[sizeof WB_HI_CLAIM]; size_t n=0;
    if(wb_hi_read(WB_HI_SAVE_CLAIM,saved,sizeof saved,&n,why)<0) return SSH_ERROR;
    if(n!=sizeof WB_HI_CLAIM-1 || memcmp(saved,WB_HI_CLAIM,n)) {
        *why="HOST ID CLAIM INVALID";return SSH_ERROR;
    }
    return SSH_OK;
}
/* AppUtil handles the title's save storage; relative names, default slot and
 * mount, ordinary file writes. No private data goes outside the save API. */
static int wb_hi_save(SceAppUtilSaveDataFile *entries,unsigned count,const char *op,const char **why) {
    SceSize required=0;
    int rc=sceAppUtilSaveDataDataSave(NULL,entries,count,NULL,&required);
    return rc==0?0:wb_hi_error(why,op,rc);
}
static int wb_host_identity_get_ex(ssh_key *out,const char **why,bool allow_new) {
    if(!out || !why) return SSH_ERROR;
    *out=NULL;
    const int ld=wb_hi_kind(WB_HI_DIR,NULL,"LEGACY DIR",why);
    if(ld==WB_HI_IO) return SSH_ERROR;
    const int ls=wb_hi_kind(WB_HI_SEAL,NULL,"LEGACY SEAL",why);
    if(ls==WB_HI_IO) return SSH_ERROR;
    int claim=wb_hi_kind(WB_HI_SAVE_CLAIM,NULL,"CLAIM STAT",why);
    if(claim==WB_HI_IO) return SSH_ERROR;
    int k=wb_hi_kind(WB_HI_SAVE_KEY,NULL,"KEY STAT",why);
    if(k==WB_HI_IO) return SSH_ERROR;
    int s=wb_hi_kind(WB_HI_SAVE_SEAL,NULL,"SEAL STAT",why);
    if(s==WB_HI_IO) return SSH_ERROR;
    bool has_save=claim!=WB_HI_MISSING || k!=WB_HI_MISSING || s!=WB_HI_MISSING;
    if(ld!=WB_HI_MISSING || ls!=WB_HI_MISSING) {
        *why="HOST ID CONFLICT";
        if(has_save) return SSH_ERROR;
        *why="HOST ID LEGACY INCOMPLETE";
        if(ld!=WB_HI_DIRECTORY || ls!=WB_HI_REGULAR) return SSH_ERROR;
        return wb_hi_load(WB_HI_KEY,WB_HI_SEAL,out,NULL,why);
    }
    if(has_save) {
        *why="HOST ID SAVE INCOMPLETE";
        if(claim!=WB_HI_REGULAR || k!=WB_HI_REGULAR || s!=WB_HI_REGULAR) return SSH_ERROR;
        if(wb_hi_claim_read(why)!=0) return SSH_ERROR;
        return wb_hi_load(WB_HI_SAVE_KEY,WB_HI_SAVE_SEAL,out,NULL,why);
    }
    if(!allow_new) { *why="HOST ID OWNER CONFIRM";return SSH_ERROR; }

    /* Single writer: only INAP00018's sole main startup path can write its
     * own title save, before the listener. Any persisted partial claim is
     * preserved, never resumed or attributed to this invocation. */
    char marker[]=WB_HI_CLAIM;
    SceAppUtilSaveDataFile probe={.filePath=WB_HI_CLAIM_NAME,.buf=marker,
        .bufSize=(SceSize)(sizeof marker-1),.mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE};
    if(wb_hi_save(&probe,1,"CLAIM SAVE",why)<0 || wb_hi_claim_read(why)<0) return SSH_ERROR;
    k=wb_hi_kind(WB_HI_SAVE_KEY,NULL,"CHECK KEY",why);
    if(k==WB_HI_IO) return SSH_ERROR;
    s=wb_hi_kind(WB_HI_SAVE_SEAL,NULL,"CHECK SEAL",why);
    if(s==WB_HI_IO) return SSH_ERROR;
    if(k!=WB_HI_MISSING || s!=WB_HI_MISSING) { *why="HOST ID CONFLICT";return SSH_ERROR; }

    int rc=SSH_ERROR; ssh_key cand=NULL;char *text=NULL;
    unsigned char expected[32],*record=NULL;size_t record_len=0;
    *why="HOST ID GENERATE";
    if(ssh_pki_generate_key(SSH_KEYTYPE_ECDSA_P256,0,&cand)!=SSH_OK ||
       wb_hi_fingerprint(cand,expected)<0) goto done;
    *why="HOST ID ENCODE";
    if(ssh_pki_export_privkey_base64_format(cand,NULL,NULL,NULL,&text,SSH_FILE_FORMAT_OPENSSH)!=SSH_OK || !text) goto done;
    size_t n=strlen(text);
    if(!n || n>WB_HI_MAX-WB_HI_PREFIX) goto done;
    record_len=WB_HI_PREFIX+n;
    *why="HOST ID MEMORY";record=malloc(record_len);
    if(!record) goto done;
    memcpy(record,WB_HI_TAG,8);memcpy(record+WB_HI_PREFIX,text,n);
    wb_hi_checksum(record+WB_HI_PREFIX,n,record+8);
    SceAppUtilSaveDataFile files[2]={
        {.filePath=WB_HI_KEY_NAME,.buf=record,.bufSize=(SceSize)record_len,
         .mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE},
        {.filePath=WB_HI_SEAL_NAME,.buf=expected,.bufSize=(SceSize)sizeof expected,
         .mode=SCE_APPUTIL_SAVEDATA_DATA_SAVE_MODE_FILE}
    };
    if(wb_hi_save(files,2,"KEY SAVE",why)<0 || wb_hi_claim_read(why)!=0) goto done;
    rc=wb_hi_load(WB_HI_SAVE_KEY,WB_HI_SAVE_SEAL,out,expected,why);
done:
    if(record) { wb_hi_wipe(record,record_len);free(record); }
    if(text) { wb_hi_wipe(text,strlen(text));ssh_string_free_char(text); }
    ssh_key_free(cand);return rc;
}
/* Explicit provisioning predicates for offline lifecycle fixtures. Production
 * passes the result of the on-device owner-confirmation gate to ...get_ex. */
static inline int wb_host_identity_acquire_ex(ssh_key *out,const char **why) {
    return wb_host_identity_get_ex(out,why,true);
}
static inline int wb_host_identity_acquire(ssh_key *out) {
    const char *why=NULL;return wb_host_identity_acquire_ex(out,&why);
}
#endif
