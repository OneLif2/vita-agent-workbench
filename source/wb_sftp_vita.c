#include "wb_sftp_vita.h"
#include "wb_ext_path_policy.h"
#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <stdlib.h>
#include <string.h>

/* Bounded per lookup (all components combined). Listing uses an existing
 * directory handle and does not require a scan per returned entry. */
#ifdef __vita__
enum { LOOKUP_LIMIT=4096, DEPTH_LIMIT=12 };
#else
enum { LOOKUP_LIMIT=512, DEPTH_LIMIT=12 };
#endif

static int native_status(int rc) {
    if ((uint32_t)rc==UINT32_C(0x80010002)) return WB_SFTP_NO_FILE;
    if ((uint32_t)rc==UINT32_C(0x8001000d)) return WB_SFTP_DENIED;
    return WB_SFTP_FAILURE;
}

static int attributes(const SceIoStat *st, wb_sftp_attr *a) {
    if (!SCE_S_ISDIR(st->st_mode) && !SCE_S_ISREG(st->st_mode)) return WB_SFTP_DENIED;
    if (SCE_S_ISREG(st->st_mode) && st->st_size < 0) return WB_SFTP_FAILURE;
    a->is_dir = !!SCE_S_ISDIR(st->st_mode);
    a->size = a->is_dir ? 0 : (uint64_t)st->st_size;
    a->mtime = 0; /* unknown UTC offset for filesystem clock: omit, do not fabricate epoch */
    return WB_SFTP_OK;
}

/* Do not follow an on-disk link while validating it with a path-based stat.
 * Look at the entry in its parent instead, including the fixed root itself.
 * Exact comparison intentionally refuses filesystem spelling aliases. */
static int child_attr(const char *parent, const char *name, size_t len,
                      unsigned *budget, wb_sftp_attr *attr) {
    int fd=sceIoDopen(parent);
    if (fd<0) return native_status(fd);
    SceIoDirent entry;
    int result=WB_SFTP_FAILURE;
    while (*budget) {
        --*budget;
        memset(&entry,0,sizeof entry);
        int n=sceIoDread(fd,&entry);
        if (n<0) { result=native_status(n); break; }
        if (!n) { result=WB_SFTP_NO_FILE; break; }
        const char *nul=memchr(entry.d_name,0,sizeof entry.d_name);
        if (!nul) break;
        if ((size_t)(nul-entry.d_name)==len && memcmp(entry.d_name,name,len)==0) {
            result=attributes(&entry.d_stat,attr);
            break;
        }
    }
    return sceIoDclose(fd)<0 ? WB_SFTP_FAILURE : result;
}

static int resolve(const char *path, char native[WB_CMD_ARG_MAX], wb_sftp_attr *attr) {
    const char *root=WB_INCOMING;
    const size_t root_n=sizeof(WB_INCOMING)-1;
    if (!path || path[0]!='/' || !attr) return WB_SFTP_DENIED;
    size_t len=strlen(path);
    if (len>1 && (path[len-1]=='/' || len>=WB_CMD_ARG_MAX-root_n)) return WB_SFTP_DENIED;
    memcpy(native,root,root_n+1);
    if (len>1) memcpy(native+root_n,path,len+1);
    /* Reuse the core's current operand policy as an additional restriction;
     * the only root assigned above is WB_INCOMING, never WB_ROOT. */
    if (!wb_ext_path_ok(native,false)) return WB_SFTP_DENIED;
    const char *p=path+1;
    unsigned depth=0;
    while (*p) {
        const char *slash=strchr(p,'/');
        size_t n=slash?(size_t)(slash-p):strlen(p);
        if (++depth>DEPTH_LIMIT || !wb_sftp_name_ok(p,n)) return WB_SFTP_DENIED;
        if (!slash) break;
        p=slash+1;
    }
    unsigned budget=LOOKUP_LIMIT;
    /* A mount root (ux0:/) is a trusted platform boundary. WB_INCOMING
     * is a trusted literal, checked as a single child rather than opened
     * before confirming that it really is a directory. */
    const char *root_name=strrchr(root,'/');
    if (!root_name || root_name==root) return WB_SFTP_FAILURE;
    size_t mount_n=(size_t)(root_name+1-root);
    native[mount_n]=0;
    int rc=child_attr(native,root_name+1,strlen(root_name+1),&budget,attr);
    memcpy(native,root,root_n+1);
    if (rc!=WB_SFTP_OK || !attr->is_dir) return rc==WB_SFTP_OK ? WB_SFTP_DENIED : rc;
    p=path+1;
    size_t used=root_n;
    while (*p) {
        const char *slash=strchr(p,'/');
        size_t n=slash?(size_t)(slash-p):strlen(p);
        if (!attr->is_dir) return WB_SFTP_DENIED;
        rc=child_attr(native,p,n,&budget,attr);
        if (rc!=WB_SFTP_OK) return rc;
        native[used++]='/';
        memcpy(native+used,p,n);
        native[used+=n]=0;
        if (!slash) break;
        p=slash+1;
    }
    return WB_SFTP_OK;
}

static int v_stat(void *ctx,const char *path,wb_sftp_attr *attr) {
    (void)ctx;
    char native[WB_CMD_ARG_MAX];
    return resolve(path,native,attr);
}
#ifdef __vita__
enum { SFTP_RBUF_SIZE = 262144u };
static struct {
    int fd;
    uint64_t off;
    size_t len;
    uint8_t *buf;
} sftp_rcache = { .fd = -1 };
static void sftp_rcache_drop(int fd, bool free_buf) {
    if (sftp_rcache.fd == fd) { sftp_rcache.fd = -1; sftp_rcache.len = 0; }
    if (free_buf && sftp_rcache.fd < 0 && sftp_rcache.buf) {
        free(sftp_rcache.buf);
        sftp_rcache.buf = NULL;
    }
}
#endif
static int v_open(void *ctx,const char *path,int dir,int *fd) {
    (void)ctx;
    if (!fd) return WB_SFTP_FAILURE;
    *fd=-1;
    char native[WB_CMD_ARG_MAX];wb_sftp_attr attr;
    int rc=resolve(path,native,&attr);
    if (rc!=WB_SFTP_OK) return rc;
    if (attr.is_dir!=dir) return WB_SFTP_DENIED;
    int opened=dir?sceIoDopen(native):sceIoOpen(native,SCE_O_RDONLY,0);
    if (opened<0) return native_status(opened);
#ifdef __vita__
    if (!dir) sftp_rcache_drop(opened, false);
#endif
    *fd=opened;
    return WB_SFTP_OK;
}
static int v_close(void *ctx,int fd,int dir) {
    (void)ctx;
#ifdef __vita__
    if (!dir) sftp_rcache_drop(fd, true);
#endif
    return (dir?sceIoDclose(fd):sceIoClose(fd))<0 ? WB_SFTP_FAILURE : WB_SFTP_OK;
}
static int v_read(void *ctx,int fd,uint64_t off,uint8_t *buf,size_t cap,size_t *got) {
    (void)ctx;
    if (!got || !buf || cap>WB_SFTP_DATA_MAX || off>INT64_MAX) return WB_SFTP_FAILURE;
    *got=0;
    if (!cap) return WB_SFTP_OK;
#ifdef __vita__
    if (sftp_rcache.fd == fd && sftp_rcache.buf &&
        off >= sftp_rcache.off && off < sftp_rcache.off + sftp_rcache.len) {
        size_t pos = (size_t)(off - sftp_rcache.off);
        size_t avail = sftp_rcache.len - pos;
        size_t take = cap < avail ? cap : avail;
        memcpy(buf, sftp_rcache.buf + pos, take);
        *got = take;
        return WB_SFTP_OK;
    }
    if (!sftp_rcache.buf) sftp_rcache.buf = (uint8_t *)malloc(SFTP_RBUF_SIZE);
    if (sftp_rcache.buf) {
        if (sceIoLseek(fd,(SceOff)off,SCE_SEEK_SET)!=(SceOff)off) return WB_SFTP_FAILURE;
        int n = sceIoRead(fd, sftp_rcache.buf, SFTP_RBUF_SIZE);
        if (n < 0 || (size_t)n > SFTP_RBUF_SIZE) { sftp_rcache_drop(fd, false); return WB_SFTP_FAILURE; }
        if (n == 0) { sftp_rcache_drop(fd, false); return WB_SFTP_EOF; }
        sftp_rcache.fd = fd;
        sftp_rcache.off = off;
        sftp_rcache.len = (size_t)n;
        size_t take = cap < (size_t)n ? cap : (size_t)n;
        memcpy(buf, sftp_rcache.buf, take);
        *got = take;
        return WB_SFTP_OK;
    }
#endif
    if (sceIoLseek(fd,(SceOff)off,SCE_SEEK_SET)!=(SceOff)off) return WB_SFTP_FAILURE;
    int n=sceIoRead(fd,buf,(SceSize)cap);
    if (n<0 || (size_t)n>cap) return WB_SFTP_FAILURE;
    *got=(size_t)n;
    return n ? WB_SFTP_OK : WB_SFTP_EOF;
}
static int v_readdir(void *ctx,int fd,char *name,size_t cap,wb_sftp_attr *attr) {
    (void)ctx;
    if (!name || !cap || !attr) return WB_SFTP_FAILURE;
    /* At most two structural entries precede the next ordinary entry on FAT.
     * Malformed directory metadata never becomes a visible filename. */
    for (unsigned i=0;i<3;i++) {
        SceIoDirent entry;
        memset(&entry,0,sizeof entry);
        int n=sceIoDread(fd,&entry);
        if (n<0) return native_status(n);
        if (!n) return WB_SFTP_EOF;
        const char *end=memchr(entry.d_name,0,sizeof entry.d_name);
        if (!end) return WB_SFTP_FAILURE;
        size_t len=(size_t)(end-entry.d_name);
        if ((len==1 || len==2) && entry.d_name[0]=='.' && (len==1 || entry.d_name[1]=='.')) continue;
        if (len>=cap || !wb_sftp_name_ok(entry.d_name,len)) return WB_SFTP_DENIED;
        int rc=attributes(&entry.d_stat,attr);
        if (rc!=WB_SFTP_OK) return rc;
        memcpy(name,entry.d_name,len+1);
        return WB_SFTP_OK;
    }
    return WB_SFTP_FAILURE;
}
static int v_fstat(void *ctx,int fd,int dir,wb_sftp_attr *attr) {
    (void)ctx;
    if (!attr) return WB_SFTP_FAILURE;
    /* Reads always seek to the explicit SFTP offset, so this does not alter
     * the client's read position. Never use a re-resolved path to stat fd. */
    SceOff n=dir?0:sceIoLseek(fd,0,SCE_SEEK_END);
    if (n<0) return WB_SFTP_FAILURE;
    attr->is_dir=dir;attr->size=(uint64_t)n;attr->mtime=0;
    return WB_SFTP_OK;
}
const wb_sftp_ops wb_sftp_vita_ops={
    .ctx=NULL,.stat=v_stat,.open=v_open,.close=v_close,.read=v_read,
    .readdir=v_readdir,.fstat=v_fstat
};
#ifdef WB_TTY_FILE
/* All mutation is through the authenticated, create-only PTY storage adapter.
 * No WRITE operation opens a final pathname. CLOSE verifies staged content
 * against the digest of wire bytes before publishing (no replacing rename). */
#include "wb_tty_file.h"
#include <stdlib.h>
#define WB_SFTP_SHA_UPDATE(c,p,n) wb_sha256_update((c),(p),(n))
typedef struct { void *disk; wb_sha256 hash; } sftp_upload;
static int write_path(const char *path,char native[WB_CMD_ARG_MAX]){
    if(!path||path[0]!='/'||!path[1]||strlen(path)>=WB_CMD_ARG_MAX-(sizeof WB_INCOMING-1))return 0;
    strcpy(native,WB_INCOMING);strcat(native,path);return 1;
}
static int create_rc(const char *why){
    if(!why)return WB_SFTP_OK;
    if(strstr(why,"denied")||strstr(why,"exists")||strstr(why,"clobber"))return WB_SFTP_DENIED;
    return WB_SFTP_FAILURE;
}
static int create_open(void *ctx,const char *path,void **out){
    (void)ctx;char native[WB_CMD_ARG_MAX];*out=NULL;
    if(!write_path(path,native))return WB_SFTP_DENIED;
    sftp_upload *u=calloc(1,sizeof *u);if(!u)return WB_SFTP_FAILURE;
    const char *why=wb_tty_vopen_stream(native,&u->disk);
    if(why){free(u);return create_rc(why);}
#ifndef __vita__
    wb_sha256_init(&u->hash);
#endif
    *out=u;return WB_SFTP_OK;
}
static int create_write(void *ctx,void *upload,const uint8_t *data,size_t n){
    (void)ctx;sftp_upload *u=upload;
    const char *why=wb_tty_vwrite(u->disk,data,n);
#ifndef __vita__
    if(!why)WB_SFTP_SHA_UPDATE(&u->hash,data,n);
#endif
    return create_rc(why);
}
static int create_finish(void *ctx,void *upload,int commit){
    (void)ctx;sftp_upload *u=upload;
#ifdef __vita__
    /* Core 1 async writer hashes every sequential wire block in parallel with SSH decrypt. */
    int rc=create_rc(wb_tty_vfinish(u->disk,commit!=0,NULL));
#else
    uint8_t digest[32];char hex[65];
    if(commit){wb_sha256_final(&u->hash,digest);wb_sha_hex(digest,sizeof digest,hex);}
    int rc=create_rc(wb_tty_vfinish(u->disk,commit!=0,commit?hex:NULL));
#endif
    free(u);return rc;
}
static int create_dir(void *ctx,const char *path){
    (void)ctx;char native[WB_CMD_ARG_MAX];
    return write_path(path,native)?create_rc(wb_tty_vmkdir(native)):WB_SFTP_DENIED;
}
const wb_sftp_write_ops wb_sftp_vita_write_ops={NULL,create_open,create_write,create_finish,create_dir};
#endif
