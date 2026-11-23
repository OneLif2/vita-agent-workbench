#include "wb_updater.h"

#include "wb_err.h"
#include "wb_head.h"
#include "wb_handoff.h"
#include "wb_sha256.h"
#include "wb_ver.h"
#include "wb_vita_install.h"
#include "wb_vita_io.h"

#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>

#include <stdio.h>
#include <string.h>

/* Embedded by `ld -r -b binary` in build.sh (updater/eboot.bin + param.sfo). */
extern const unsigned char _binary_updater_eboot_bin_start[];
extern const unsigned char _binary_updater_eboot_bin_end[];
extern const unsigned char _binary_updater_param_sfo_start[];
extern const unsigned char _binary_updater_param_sfo_end[];

/* Only shipped helper pairs audited to perform final WBQ2 and R1 checks.
 * The common SFO covers the complete TITLE_ID/APP_VER, not just a title name.
 * Freeze 01.74 for initial provisioning; change this allowlist only after a
 * new compatibility review (never learn a new digest from an installed app). */
#define UP_ROOT "ux0:/app/" WB_UPDATER_TITLE_ID
#define UP_NOT_FOUND ((int)0x80010002u)
#define UP_BOOT_SIZE 161438u
#define UP_SFO_SIZE  912u
static const char boot73[]="53bc94ee1418a73339965da45a110562caa34bd63778c7f81f21e63f2e1189a8";
static const char boot74[]="3db1718a22be8c4a2916e41e2dae1d1930fd881c958b7163862f76b6093deb3b";
static const char meta[]="1dba3e69e2647c12bf6a094c291dc210cdc651b7bbad11c3d6cdef63b3a4fe1b";

static const char *decision="helper=unchecked";
const char *wb_updater_decision(void) { return decision; }

static int reject(const char *event,int err,int native,int *detail) {
    decision=event; *detail=native; return err;
}

static void sha_finish(wb_sha256 *ctx,char hex[65]) {
    uint8_t out[32]; wb_sha256_final(ctx,out); wb_sha_hex(out,sizeof out,hex);
}

static int member_state(const char *path,bool dir,unsigned len,int *present,int *detail) {
    SceIoStat st={0};
    int rc=sceIoGetstat(path,&st);
    if(rc==UP_NOT_FOUND) { *present=0; return WB_OK; }
    if(rc<0) { *detail=rc; return WB_E_IO; }
    if(dir?!SCE_S_ISDIR(st.st_mode):(!SCE_S_ISREG(st.st_mode)||st.st_size!=len))
        return WB_E_FORMAT;
    *present=1; return WB_OK;
}

static int hash_file(const char *path,unsigned bytes,char hex[65],int *detail) {
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);
    if(fd<0) { *detail=fd; return WB_E_IO; }
    uint8_t buf[1024]; wb_sha256 sha;
    unsigned left=bytes; int rc=WB_OK;
    wb_sha256_init(&sha);
    while(left) {
        unsigned chunk=left<sizeof buf?left:sizeof buf;
        int n=sceIoRead(fd,buf,chunk);
        if(n<=0 || (unsigned)n>chunk) { *detail=n; rc=WB_E_IO; break; }
        wb_sha256_update(&sha,buf,(size_t)n); left-=(unsigned)n;
    }
    if(rc==WB_OK) {
        int n=sceIoRead(fd,buf,1);
        if(n!=0) { *detail=n; rc=n<0?WB_E_IO:WB_E_FORMAT; }
    }
    int close_rc=sceIoClose(fd);
    if(rc==WB_OK && close_rc<0) { *detail=close_rc; rc=WB_E_IO; }
    if(rc==WB_OK)sha_finish(&sha,hex);
    return rc;
}

/* Read-only production decision. Do not bootstrap an unregistered but
 * present title, a registered but missing title, or an unreadable title. */
int wb_updater_probe(int *detail) {
    if(!detail)return WB_E_ARG;
    *detail=0;
    int db=-1,root=-1,boot=-1,sfo=-1;
    decision="helper=refuse phase=registration";
    int rc=wb_vita_updater_registered(&db,detail);
    if(rc!=WB_OK)return rc;
    if(db!=0 && db!=1)return WB_E_STATE;
    decision="helper=refuse phase=title-dir";
    if((rc=member_state(UP_ROOT,true,0,&root,detail))!=WB_OK)return rc;
    decision="helper=refuse phase=eboot-stat";
    if((rc=member_state(UP_ROOT "/eboot.bin",false,UP_BOOT_SIZE,&boot,detail))!=WB_OK)return rc;
    decision="helper=refuse phase=sfo-stat";
    if((rc=member_state(UP_ROOT "/sce_sys/param.sfo",false,UP_SFO_SIZE,&sfo,detail))!=WB_OK)return rc;
    if(root!=db||boot!=db||sfo!=db)
        return reject("helper=refuse phase=partial-or-unregistered",WB_E_STATE,0,detail);
    if(!db) { decision="helper=absent promote=0"; *detail=0; return WB_OK; }
    char b[65],m[65];
    decision="helper=refuse phase=eboot-read";
    if((rc=hash_file(UP_ROOT "/eboot.bin",UP_BOOT_SIZE,b,detail))!=WB_OK)return rc;
    decision="helper=refuse phase=sfo-read";
    if((rc=hash_file(UP_ROOT "/sce_sys/param.sfo",UP_SFO_SIZE,m,detail))!=WB_OK)return rc;
    if(strcmp(m,meta) || (strcmp(b,boot73) && strcmp(b,boot74)))
        return reject("helper=refuse phase=unknown-identity",WB_E_SHA,0,detail);
    decision=!strcmp(b,boot74)?"helper=reuse epoch=01.74 promote=0":"helper=reuse epoch=01.73 promote=0";
    *detail=1;
    return WB_OK;
}

static bool blob_matches(const unsigned char *start,const unsigned char *end,
                         unsigned size,const char *expected) {
    if((uintptr_t)end<(uintptr_t)start || (uintptr_t)end-(uintptr_t)start!=size)return false;
    wb_sha256 sha; char hex[65];
    wb_sha256_init(&sha); wb_sha256_update(&sha,start,size); sha_finish(&sha,hex);
    return !strcmp(hex,expected);
}

bool wb_updater_available(void) {
    return blob_matches(_binary_updater_eboot_bin_start,_binary_updater_eboot_bin_end,UP_BOOT_SIZE,boot74) &&
           blob_matches(_binary_updater_param_sfo_start,_binary_updater_param_sfo_end,UP_SFO_SIZE,meta);
}

static int write_blob(const char *path,const unsigned char *start,size_t len,int *detail) {
    int fd=sceIoOpen(path,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0666);
    if(fd<0) { *detail=fd; return WB_E_IO; }
    int rc=WB_OK;
    while(len) {
        int n=sceIoWrite(fd,start,(SceSize)len);
        if(n<=0 || (size_t)n>len) { *detail=n; rc=WB_E_IO; break; }
        start+=n; len-=(size_t)n;
    }
    int close_rc=sceIoClose(fd);
    if(rc==WB_OK && close_rc<0) { *detail=close_rc; return WB_E_IO; }
    return rc;
}

int wb_updater_install(int *detail) {
    int local=0;
    if(!detail)detail=&local;
    int rc=wb_updater_probe(detail);
    if(rc!=WB_OK || *detail==1)return rc;  /* exact reuse: no stage, no promote */
    if(!wb_updater_available())
        return reject("helper=refuse phase=embedded-identity",WB_E_SHA,0,detail);
    decision="helper=refuse phase=stage";
    SceIoStat st={0};
    int native=sceIoGetstat(WB_UPDATER_STAGE,&st);
    if(native!=UP_NOT_FOUND) {
        if(native<0) { *detail=native; return WB_E_IO; }
        if(!SCE_S_ISDIR(st.st_mode))return WB_E_FORMAT;
        if((rc=wb_vita_remove_tree(WB_UPDATER_STAGE))!=WB_OK)return rc;
    }
    if((rc=wb_vita_mkdir_p(WB_UPDATER_STAGE "/sce_sys/package"))!=WB_OK)return rc;
    if((rc=write_blob(WB_UPDATER_STAGE "/eboot.bin",_binary_updater_eboot_bin_start,UP_BOOT_SIZE,detail))!=WB_OK)return rc;
    if((rc=write_blob(WB_UPDATER_STAGE "/sce_sys/param.sfo",_binary_updater_param_sfo_start,UP_SFO_SIZE,detail))!=WB_OK)return rc;
    uint8_t head[WB_HEAD_SIZE];
    if((rc=wb_head_build(head,sizeof head,WB_UPDATER_TITLE_ID,NULL))!=WB_OK)return rc;
    if((rc=write_blob(WB_UPDATER_STAGE "/sce_sys/package/head.bin",head,sizeof head,detail))!=WB_OK)return rc;
    /* Refuse to promote over a title that appeared while we prepared staging. */
    rc=wb_updater_probe(detail);
    if(rc!=WB_OK || *detail==1)return rc;
    wb_handoff_note("helper=bootstrap epoch=01.74 promote=submit",0);
    decision="helper=refuse phase=promote-issued";
    if((rc=wb_vita_promote_stage(WB_UPDATER_STAGE,true,detail))!=WB_OK)return rc;
    rc=wb_updater_probe(detail);
    if(rc!=WB_OK)return rc;
    if(*detail!=1 || strcmp(decision,"helper=reuse epoch=01.74 promote=0"))
        return reject("helper=refuse phase=post-install-identity",WB_E_STATE,0,detail);
    decision="helper=installed epoch=01.74 promote=1"; *detail=0;
    return WB_OK;
}

int wb_updater_launch(void) {
    wb_handoff_note("core->updater request", 0);
    int rc = sceAppMgrLaunchAppByUri(WB_HANDOFF_APP_URI, "psgm:play?titleid=" WB_UPDATER_TITLE_ID);
    wb_handoff_note("core->updater reply", rc);
    return rc;
}
