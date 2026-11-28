#include "wb_transfer_limits.h"
#include "wb_game_logs_path.h"
#include "wb_shell_vfs.h"
/* Adapter for the authenticated interactive shell. This opens files, not a
 * second SSH connection. Upload data stays private until the final SHA matches. */
enum { TTY_STREAM_WBUF=262144u, TTY_HASH_RBUF=524288u, TTY_ASYNC_SLOTS=8u };
#ifdef __vita__
typedef struct {
    SceUID thid, sema_data, sema_free;
    uint8_t *ring;
    size_t slot_len[TTY_ASYNC_SLOTS];
    volatile unsigned head, tail;
    volatile bool stop, abort_now, failed;
    int fd;
    uint64_t written;
    wb_sha256 sha;
    char err[128];
} tty_async_wr;
static int tty_async_entry(SceSize args, void *argp) {
    (void)args;
    tty_async_wr *aw = *(tty_async_wr **)argp;
    for (;;) {
        if (sceKernelWaitSema(aw->sema_data, 1, NULL) < 0) break;
        __sync_synchronize();
        if (aw->tail == aw->head && aw->stop) break;
        const unsigned slot = aw->tail % TTY_ASYNC_SLOTS;
        const size_t n = aw->slot_len[slot];
        const uint8_t *p = aw->ring + (size_t)slot * TTY_STREAM_WBUF;
        if (!aw->failed && !aw->abort_now) {
            wb_sha256_update(&aw->sha, p, n);
            for (size_t off = 0; off < n;) {
                const size_t rem = n - off;
                const int k = sceIoWrite(aw->fd, p + off, (SceSize)rem);
                if (k <= 0 || (size_t)k > rem) {
                    snprintf(aw->err, sizeof aw->err,
                        "write-error rc=0x%08x offset=%llu requested=%u fd=%d",
                        (unsigned)k, (unsigned long long)aw->written, (unsigned)rem, aw->fd);
                    __sync_synchronize();
                    aw->failed = true;
                    break;
                }
                off += (size_t)k;
                aw->written += (uint64_t)k;
            }
        }
        aw->tail++;
        __sync_synchronize();
        (void)sceKernelSignalSema(aw->sema_free, 1);
    }
    return sceKernelExitThread(0);
}
static tty_async_wr *tty_async_create(int fd) {
    tty_async_wr *aw = calloc(1, sizeof *aw);
    if (!aw) return NULL;
    aw->fd = fd;
    aw->thid = -1; aw->sema_data = -1; aw->sema_free = -1;
    wb_sha256_init(&aw->sha);
    aw->ring = malloc((size_t)TTY_ASYNC_SLOTS * TTY_STREAM_WBUF);
    if (!aw->ring) goto bad;
    aw->sema_data = sceKernelCreateSema("wb_sftp_d", 0, 0, TTY_ASYNC_SLOTS + 2, NULL);
    aw->sema_free = sceKernelCreateSema("wb_sftp_f", 0, TTY_ASYNC_SLOTS, TTY_ASYNC_SLOTS, NULL);
    if (aw->sema_data < 0 || aw->sema_free < 0) goto bad;
    aw->thid = sceKernelCreateThread("wb_sftp_w", tty_async_entry, 0x10000100, 0x8000, 0, 0x00020000, NULL);
    if (aw->thid < 0) aw->thid = sceKernelCreateThread("wb_sftp_w", tty_async_entry, 0x10000100, 0x8000, 0, 0, NULL);
    if (aw->thid < 0) goto bad;
    if (sceKernelStartThread(aw->thid, sizeof aw, &aw) < 0) {
        (void)sceKernelDeleteThread(aw->thid); aw->thid = -1;
        goto bad;
    }
    return aw;
bad:
    if (aw->sema_data >= 0) (void)sceKernelDeleteSema(aw->sema_data);
    if (aw->sema_free >= 0) (void)sceKernelDeleteSema(aw->sema_free);
    free(aw->ring);
    free(aw);
    return NULL;
}
static const char *tty_async_push(tty_async_wr *aw, const uint8_t *p, size_t n, char dst_err[128]) {
    if (aw->failed) { memcpy(dst_err, aw->err, 128); return dst_err; }
    if (sceKernelWaitSema(aw->sema_free, 1, NULL) < 0) {
        snprintf(dst_err, 128, "write-error rc=0xffffffff offset=%llu requested=%u fd=%d",
                 (unsigned long long)aw->written, (unsigned)n, aw->fd);
        return dst_err;
    }
    __sync_synchronize();
    if (aw->failed) {
        (void)sceKernelSignalSema(aw->sema_free, 1);
        memcpy(dst_err, aw->err, 128);
        return dst_err;
    }
    const unsigned slot = aw->head % TTY_ASYNC_SLOTS;
    memcpy(aw->ring + (size_t)slot * TTY_STREAM_WBUF, p, n);
    aw->slot_len[slot] = n;
    __sync_synchronize();
    aw->head++;
    __sync_synchronize();
    (void)sceKernelSignalSema(aw->sema_data, 1);
    return NULL;
}
static void tty_async_join(tty_async_wr *aw, bool abort_now, uint64_t *written_out, char dst_err[128], char sha_hex_out[65]) {
    if (!aw) return;
    if (abort_now) aw->abort_now = true;
    aw->stop = true;
    __sync_synchronize();
    (void)sceKernelSignalSema(aw->sema_data, 1);
    (void)sceKernelWaitThreadEnd(aw->thid, NULL, NULL);
    __sync_synchronize();
    if (written_out) *written_out = aw->written;
    if (aw->failed && dst_err && !dst_err[0]) memcpy(dst_err, aw->err, 128);
    if (sha_hex_out) {
        if (!abort_now && !aw->failed) {
            uint8_t raw[32];
            wb_sha256_final(&aw->sha, raw);
            wb_sha_hex(raw, sizeof raw, sha_hex_out);
        } else {
            sha_hex_out[0] = 0;
        }
    }
    (void)sceKernelDeleteThread(aw->thid);
    (void)sceKernelDeleteSema(aw->sema_data);
    (void)sceKernelDeleteSema(aw->sema_free);
    free(aw->ring);
    free(aw);
}
#endif
#define WB_FAST_SHA_UPDATE(c,p,n) wb_sha256_update((c),(p),(n))
#ifndef WB_VERIFY_PULSE
#define WB_VERIFY_PULSE(done,total) ((void)0)
#endif
typedef struct {
    int fd; bool put,stream,sync_sha_on;
    char stage[128],dest[WB_CMD_ARG_MAX];
    uint64_t size,offset,space_credit;
    uint8_t *wbuf; size_t wlen;
    wb_sha256 sync_sha;
#ifdef __vita__
    tty_async_wr *aw;
#endif
    char write_error[128]; /* sticky: never publish after a partial frame */
} wb_tty_disk;
static unsigned tty_serial;
static bool tty_noreplace_seen;
static int tty_nofile(const char *p){
    SceIoStat st;memset(&st,0,sizeof st);
    return (uint32_t)sceIoGetstat(p,&st)==UINT32_C(0x80010002);
}
static int tty_private_name(char p[128]){
    if(tty_serial==UINT32_MAX)return 0;
    int n=snprintf(p,128,WB_ROOT "/tty-%s-%08x.tmp",a.run_hex,++tty_serial);
    return n>0 && n<128 && tty_nofile(p);
}
/* ux0 has historically rejected O_EXCL. Never fall back to opening the
 * public destination for writing. Test same-volume rename-to-existing using
 * two disposable PRIVATE siblings; refuse publication on replacing filesystems. */
static bool tty_noreplace(void){
    if(tty_noreplace_seen)return true;
    char ap[128],bp[128];if(!tty_private_name(ap)||!tty_private_name(bp))return false;
    int a_fd=open_staging(ap,NULL);if(a_fd<0)return false;
    int b_fd=open_staging(bp,NULL);
    bool ok=b_fd>=0 && sceIoWrite(a_fd,"A",1)==1 && sceIoWrite(b_fd,"B",1)==1;
    if(sceIoClose(a_fd)<0)ok=false;
    if(b_fd>=0 && sceIoClose(b_fd)<0)ok=false;
    if(ok){
        int rc=sceIoRename(ap,bp);
        char a1=0,b1=0;size_t na=0,nb=0;
        ok=(uint32_t)rc==UINT32_C(0x80010011) &&
           wb_vita_read_small(ap,&a1,1,&na)==WB_OK && na==1 && a1=='A' &&
           wb_vita_read_small(bp,&b1,1,&nb)==WB_OK && nb==1 && b1=='B';
    }
    if(!tty_nofile(ap) && sceIoRemove(ap)<0)ok=false;
    if(b_fd>=0 && sceIoRemove(bp)<0)ok=false;
    if(ok)tty_noreplace_seen=true;
    return ok;
}
static int tty_budget_sink(void *c,const char *p,size_t n){(void)c;(void)p;(void)n;return WB_OK;}
/* WB_INCOMING is the only writable root. Validate every component before
 * use; the SFTP resolver checks directory entries without following links. */
static bool tty_path(const char *p){
    if(!p||strlen(p)>=WB_CMD_ARG_MAX||strncmp(p,WB_INCOMING "/",sizeof WB_INCOMING))return false;
    p+=sizeof WB_INCOMING;
    unsigned depth=0;
    for(;;){
        const char *slash=strchr(p,'/');size_t n=slash?(size_t)(slash-p):strlen(p);
        if(++depth>12||!n||n>100||p[0]==' '||p[n-1]==' '||p[n-1]=='.')return false;
        for(size_t i=0;i<n;i++){
            unsigned c=(unsigned char)p[i];
            if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
                 strchr("_(). +@-",(int)c)))return false;
        }
        if(!slash)return true;
        p=slash+1;
    }
}
static bool tty_parent(const char *p){
    const char *v=p+sizeof(WB_INCOMING)-1,*end=strrchr(v,'/');
    char parent[WB_CMD_ARG_MAX];size_t n=(size_t)(end-v);
    if(!n)n=1;
    memcpy(parent,v,n);parent[n]=0;
    wb_sftp_attr attr;
    return wb_sftp_vita_ops.stat(NULL,parent,&attr)==WB_SFTP_OK&&attr.is_dir;
}
const char *wb_tty_vprobe(const char *p,const char **kind){
    bool root=p&&!strcmp(p,WB_INCOMING);
    if(!kind||(!root&&(!tty_path(p)||!tty_parent(p))))return "path-denied";
    const char *v=root?"/":p+sizeof(WB_INCOMING)-1;
    wb_sftp_attr attr;int rc=wb_sftp_vita_ops.stat(NULL,v,&attr);
    if(rc==WB_SFTP_OK)*kind=attr.is_dir?"DIR":"FILE";
    else if(!root&&rc==WB_SFTP_NO_FILE&&tty_nofile(p))*kind="ABSENT";
    else return "not-found-or-denied";
    return NULL;
}
const char *wb_tty_vmkdir(const char *p){
    if(!tty_path(p)||!tty_parent(p))return "path-denied";
    if(!tty_nofile(p))return "destination-exists-or-unavailable";
    if(sceIoMkdir(p,0777)<0)return "mkdir-denied";
    wb_sftp_attr a;
    return wb_sftp_vita_ops.stat(NULL,p+sizeof(WB_INCOMING)-1,&a)==WB_SFTP_OK&&a.is_dir?
           NULL:"mkdir-result-unknown";
}
static const char *tty_diag(const char *p){
    static const char *const names[]={"run.log","startup.log","install.log","timeline.txt","shot.bmp","testapp/result.txt","wake-probe/result.bin"};
    static const char prefix[]="ux0:/data/INAP00018/";
    if(strncmp(p,prefix,sizeof prefix-1))return NULL;
    for(size_t i=0;i<sizeof names/sizeof names[0];i++)if(!strcmp(p+sizeof prefix-1,names[i]))return names[i];
    return NULL;
}
static const char *tty_open(bool put,bool stream,const char *path,uint64_t expected,void **opaque,uint64_t *size){
    if(!opaque||!size||!path)return "argument";
    *opaque=NULL;*size=0;
    if(strlen(path)>=WB_CMD_ARG_MAX)return "path-denied";
    const bool incoming=!strncmp(path,WB_INCOMING "/",sizeof WB_INCOMING);
    const char *diag=put?NULL:tty_diag(path);
    const bool game_log=!put && wb_game_logs_path(path);
    if(!incoming&&!diag&&!game_log)return "path-denied";
    if(put && !tty_path(path))return "path-denied";
    if(put && expected>WB_TRANSFER_MAX)return "bad-size";
    wb_tty_disk *d=calloc(1,sizeof *d);if(!d)return "nomem";
    const char *err="io-error"; d->fd=-1;d->put=put;d->stream=stream;
    if(put){
        wb_out sink={NULL,tty_budget_sink};int budget=wb_ux0_budget(2*expected+65536,&sink,false);
        if(budget!=WB_OK){err=budget==WB_E_LIMIT?"no-space":"space-unavailable";goto fail;}
        if(wb_vita_mkdir_p(WB_ROOT)!=WB_OK||wb_vita_mkdir_p(WB_INCOMING)!=WB_OK)goto fail;
        if(!tty_parent(path)){err="path-denied";goto fail;}
        if(!tty_nofile(path)){err="destination-exists-or-unavailable";goto fail;}
        if(!tty_noreplace()){err="no-clobber-unavailable";goto fail;}
        if(!tty_private_name(d->stage))goto fail;
        d->fd=open_staging(d->stage,NULL);if(d->fd<0)goto fail;
        if(stream){
            d->wbuf=malloc(TTY_STREAM_WBUF);
#ifdef __vita__
            if(d->wbuf)d->aw=tty_async_create(d->fd);
            if(!d->aw){ wb_sha256_init(&d->sync_sha); d->sync_sha_on=true; }
#endif
        }
        strcpy(d->dest,path);d->size=expected;
    }else{
        if(incoming){
            if(wb_sftp_vita_ops.open(NULL,path+sizeof(WB_INCOMING)-1,0,&d->fd)!=WB_SFTP_OK){err="not-found-or-denied";goto fail;}
        }else if(game_log){
            if(wb_vita_shell_open_game_log(path,&d->fd)!=0){err="not-found-or-denied";goto fail;}
        }else{
            char native[128];snprintf(native,sizeof native,WB_ROOT "/%s",diag);
            d->fd=sceIoOpen(native,SCE_O_RDONLY,0);if(d->fd<0){err="not-found";goto fail;}
        }
        SceOff last=sceIoLseek(d->fd,0,SCE_SEEK_END);
        if(last<0||(uint64_t)last>WB_TRANSFER_MAX||sceIoLseek(d->fd,0,SCE_SEEK_SET)!=0){err="bad-size";goto fail;}
        d->size=(uint64_t)last;
    }
    *size=d->size;*opaque=d;return NULL;
fail:
#ifdef __vita__
    if(d->aw)tty_async_join(d->aw,true,NULL,NULL,NULL);
#endif
    if(d->fd>=0)sceIoClose(d->fd);
    free(d->wbuf);
    free(d);return err;
}
const char *wb_tty_vopen(bool put,const char *path,uint64_t expected,void **opaque,uint64_t *size){
    return tty_open(put,false,path,expected,opaque,size);
}
const char *wb_tty_vopen_stream(const char *path,void **opaque){
    uint64_t ignored=0;return tty_open(true,true,path,0,opaque,&ignored);
}
static const char *tty_flush_raw(wb_tty_disk *d,const uint8_t *p,size_t n){
#ifdef __vita__
    if(d->aw)return tty_async_push(d->aw,p,n,d->write_error);
#endif
    if(d->sync_sha_on)WB_FAST_SHA_UPDATE(&d->sync_sha,p,n);
    for(size_t off=0;off<n;){
        size_t rem=n-off;int k=sceIoWrite(d->fd,p+off,(SceSize)rem);
        if(k<=0 || (size_t)k>rem){
            snprintf(d->write_error,sizeof d->write_error,
                "write-error rc=0x%08x offset=%llu requested=%u fd=%d",
                (unsigned)k,(unsigned long long)d->offset,(unsigned)rem,d->fd);
            return d->write_error;
        }
        off+=(size_t)k;d->offset+=(uint64_t)k;
    }
    return NULL;
}
static int tty_readback_hash(const wb_reader *r,char hex[65]){
    uint8_t *buf=r->size?(uint8_t *)malloc(TTY_HASH_RBUF):NULL;
    if(r->size && !buf)return wb_checked_hash(r,hex,malloc);
    uint8_t raw[32];wb_sha256 sha;hex[0]=0;wb_sha256_init(&sha);
    WB_VERIFY_PULSE(0,r->size);
    for(uint64_t off=0;off<r->size;){
        size_t take=(r->size-off>TTY_HASH_RBUF)?TTY_HASH_RBUF:(size_t)(r->size-off);
        if(r->read_at(r->ctx,off,buf,take)!=WB_OK){free(buf);return WB_E_IO;}
        WB_FAST_SHA_UPDATE(&sha,buf,take);off+=take;
        WB_VERIFY_PULSE(off,r->size);
    }
    free(buf);wb_sha256_final(&sha,raw);wb_sha_hex(raw,sizeof raw,hex);return WB_OK;
}
const char *wb_tty_vwrite(void *opaque,const uint8_t *p,size_t n){
    wb_tty_disk *d=opaque;
    if(d && d->write_error[0])return d->write_error;
    const uint64_t accepted=d?(d->stream?d->size:d->offset):0;
    if(!d||!d->put||!p||n>(d->stream?WB_TRANSFER_MAX:d->size)-accepted)return "bad-size";
    if(d->stream&&n>d->space_credit){
        uint64_t credit=n>16777216u?n:16777216u;
        wb_out sink={NULL,tty_budget_sink};
        int b=wb_ux0_budget(credit+65536,&sink,false);
        if(b!=WB_OK)return b==WB_E_LIMIT?"no-space":"space-unavailable";
        d->space_credit=credit;
    }
    /* Preserve the actual native result before closing/unlinking anything.
     * offset counts bytes accepted by sceIoWrite, NOT durable storage. */
    if(d->stream && d->wbuf){
        size_t pos=0;
        while(pos<n){
            size_t room=TTY_STREAM_WBUF-d->wlen,take=n-pos<room?n-pos:room;
            memcpy(d->wbuf+d->wlen,p+pos,take);
            d->wlen+=take;pos+=take;
            if(d->wlen==TTY_STREAM_WBUF){
                const char *we=tty_flush_raw(d,d->wbuf,d->wlen);
                d->wlen=0;
                if(we)return we;
            }
        }
        d->size+=n;d->space_credit-=n;
        return NULL;
    }
    const char *we=tty_flush_raw(d,p,n);
    if(we)return we;
    if(d->stream){d->size=d->offset;d->space_credit-=n;}
    return NULL;
}
const char *wb_tty_vread(void *opaque,uint8_t *p,size_t cap,size_t *n){
    wb_tty_disk *d=opaque;if(!d||d->put||!p||!n)return "argument";
    if(cap>d->size-d->offset)cap=(size_t)(d->size-d->offset);
    int got=cap?sceIoRead(d->fd,p,(SceSize)cap):0;
    if(got<0||(cap&&!got)||(size_t)got>cap)return "read-error";
    *n=(size_t)got;d->offset+=*n;return NULL;
}
const char *wb_tty_vfinish(void *opaque,bool commit,const char *shahex){
    wb_tty_disk *d=opaque;if(!d)return "argument";
    const char *err=NULL;
    char worker_hex[65]={0};
    if(d->put && commit && !d->write_error[0] && d->wlen){
        (void)tty_flush_raw(d,d->wbuf,d->wlen);d->wlen=0;
    }
#ifdef __vita__
    if(d->aw){
        tty_async_join(d->aw,!commit,&d->offset,d->write_error,worker_hex);
        d->aw=NULL;
    }
#endif
    if(d->put && commit && !shahex){
        if(worker_hex[0])shahex=worker_hex;
        else if(d->sync_sha_on){
            uint8_t raw[32];wb_sha256_final(&d->sync_sha,raw);wb_sha_hex(raw,sizeof raw,worker_hex);
            shahex=worker_hex;
        }
    }
    if(commit && d->write_error[0])err=d->write_error;
    else if(commit && d->offset!=d->size)err="size-mismatch";
    if(commit && !d->put && sceIoLseek(d->fd,0,SCE_SEEK_END)!=(SceOff)d->size)err="size-changed";
    int sync_rc=d->put && commit && !err ? sceIoSyncByFd(d->fd,0):0;
    int close_rc=sceIoClose(d->fd),remove_rc=0;
    if(d->put && commit && !err && sync_rc>=0 && close_rc>=0){
        wb_reader r;wb_vfile f;char digest[65]={0};
        if(wb_vita_reader_open(d->stage,&r,&f)!=WB_OK)err="readback-error";
        else{
            if(!shahex||r.size!=d->size||tty_readback_hash(&r,digest)!=WB_OK||strcmp(digest,shahex))err="stage-hash-mismatch";
            wb_vita_reader_close(&f);
        }
        if(!err){
            if(!tty_parent(d->dest))err="path-denied";
            else if(!tty_nofile(d->dest))err="destination-exists-or-unavailable";
            else if(sceIoRename(d->stage,d->dest)<0)err="publish-denied";
            else d->stage[0]=0;
        }
    }
    if(d->put && d->stage[0])remove_rc=sceIoRemove(d->stage);
    /* finish releases the handle. The single-threaded adapter's caller
     * consumes/copies this result before the next finish, including SFTP.
     * Do not try to write a diagnostic onto the volume that just failed. */
    static char detail[384];
    snprintf(detail,sizeof detail,"%s",err?err:"");
    const int rcs[]={sync_rc,close_rc,remove_rc};
    const char *const labels[]={"sync-error","close-error","cleanup-error"};
    for(size_t i=0;i<3;i++)if(rcs[i]<0){
        size_t pos=strlen(detail);
        snprintf(detail+pos,sizeof detail-pos,"%s%s rc=0x%08x offset=%llu fd=%d",
                 pos?" ; ":"",labels[i],(unsigned)rcs[i],(unsigned long long)d->offset,d->fd);
    }
    free(d->wbuf);
    free(d);return detail[0]?detail:NULL;
}
