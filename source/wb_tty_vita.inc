/* Adapter for the authenticated interactive shell. This opens files, not a
 * second SSH connection. Upload data stays private until the final SHA matches. */
typedef struct {
    int fd; bool put,stream;
    char stage[128],dest[WB_CMD_ARG_MAX];
    uint64_t size,offset,space_credit;
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
    if(!incoming&&!diag)return "path-denied";
    if(put && !tty_path(path))return "path-denied";
    if(put && expected>WB_UPLOAD_MAX)return "bad-size";
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
        strcpy(d->dest,path);d->size=expected;
    }else{
        if(incoming){
            if(wb_sftp_vita_ops.open(NULL,path+sizeof(WB_INCOMING)-1,0,&d->fd)!=WB_SFTP_OK){err="not-found-or-denied";goto fail;}
        }else{
            char native[128];snprintf(native,sizeof native,WB_ROOT "/%s",diag);
            d->fd=sceIoOpen(native,SCE_O_RDONLY,0);if(d->fd<0){err="not-found";goto fail;}
        }
        SceOff last=sceIoLseek(d->fd,0,SCE_SEEK_END);
        if(last<0||(uint64_t)last>WB_UPLOAD_MAX||sceIoLseek(d->fd,0,SCE_SEEK_SET)!=0){err="bad-size";goto fail;}
        d->size=(uint64_t)last;
    }
    *size=d->size;*opaque=d;return NULL;
fail:
    if(d->fd>=0)sceIoClose(d->fd);
    free(d);return err;
}
const char *wb_tty_vopen(bool put,const char *path,uint64_t expected,void **opaque,uint64_t *size){
    return tty_open(put,false,path,expected,opaque,size);
}
const char *wb_tty_vopen_stream(const char *path,void **opaque){
    uint64_t ignored=0;return tty_open(true,true,path,0,opaque,&ignored);
}
const char *wb_tty_vwrite(void *opaque,const uint8_t *p,size_t n){
    wb_tty_disk *d=opaque;
    if(!d||!d->put||!p||n>(d->stream?WB_UPLOAD_MAX:d->size)-d->offset)return "bad-size";
    if(d->stream&&n>d->space_credit){
        uint64_t credit=n>65536?n:65536;
        wb_out sink={NULL,tty_budget_sink};
        int b=wb_ux0_budget(credit+65536,&sink,false);
        if(b!=WB_OK)return b==WB_E_LIMIT?"no-space":"space-unavailable";
        d->space_credit=credit;
    }
    if(write_upload_chunk(d->fd,p,n)!=WB_OK)return "write-error";
    d->offset+=n;
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
    if(commit && d->offset!=d->size)err="size-mismatch";
    if(commit && !d->put && sceIoLseek(d->fd,0,SCE_SEEK_END)!=(SceOff)d->size)err="size-changed";
    if(d->put && commit && !err && sceIoSyncByFd(d->fd,0)<0)err="sync-error";
    if(sceIoClose(d->fd)<0)err="close-error";
    if(d->put && commit && !err){
        wb_reader r;wb_vfile f;char digest[65]={0};
        if(wb_vita_reader_open(d->stage,&r,&f)!=WB_OK)err="readback-error";
        else{
            if(!shahex||r.size!=d->size||wb_checked_hash(&r,digest,malloc)!=WB_OK||strcmp(digest,shahex))err="stage-hash-mismatch";
            wb_vita_reader_close(&f);
        }
        if(!err){
            if(!tty_parent(d->dest))err="path-denied";
            else if(!tty_nofile(d->dest))err="destination-exists-or-unavailable";
            else if(sceIoRename(d->stage,d->dest)<0)err="publish-denied";
            else d->stage[0]=0;
        }
    }
    if(d->put && d->stage[0] && sceIoRemove(d->stage)<0)err="cleanup-error";
    free(d);return err;
}
