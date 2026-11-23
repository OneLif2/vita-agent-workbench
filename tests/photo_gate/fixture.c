#include "wb_photo_gate.h"
#include "wb_cmd.h"
#include "wb_vita_photo.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define P "ux0:/VITA-POC/"
#define FAKE_SHA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static int cases;
typedef struct {
    uint8_t *data,*reference;
    size_t size;
    uint64_t length;
    int opened,closed,imports,reads,openfx,statfx,readfx,closefx,import_rc,unload_rc;
    int dir,grow,truncate,mutate;
    char want[128],reply[512];
} fixture;
static fixture f;
static int op(void *ctx,const char *path,int dir,int *fd) {
    assert(ctx==&f && !dir && !strcmp(path,f.want));++f.opened;
    if (!f.openfx) *fd=9;
    return f.openfx;
}
static int cl(void *ctx,int fd,int dir) {
    assert(ctx==&f && fd==9 && !dir);++f.closed;
    if (f.mutate) memset(f.data,1,f.size);
    return f.closefx;
}
static int st(void *ctx,int fd,int dir,wb_sftp_attr *out) {
    assert(ctx==&f && fd==9 && !dir);out->size=f.length;out->is_dir=f.dir;return f.statfx;
}
static int rd(void *ctx,int fd,uint64_t off,uint8_t *p,size_t n,size_t *got) {
    assert(ctx==&f && fd==9 && n<=WB_SFTP_DATA_MAX && n && p);
    ++f.reads; *got=0;
    if (f.readfx) return f.readfx;
    if (f.truncate) return WB_SFTP_EOF;
    if (off==f.size && f.grow) { *p=11;*got=1;return WB_SFTP_OK; }
    if (off>=f.size) return WB_SFTP_EOF;
    size_t left=f.size-(size_t)off;
    if (n>left) n=left;
    if (n>47) n=47; /* positive partial I/O, including mid-header chunks */
    memcpy(p,f.data+off,n);*got=n;return WB_SFTP_OK;
}
static int write_reply(void *ctx,const char *s,size_t n) {
    assert(ctx==&f && strlen(f.reply)+n+1<=sizeof f.reply);
    strncat(f.reply,s,n);return 0;
}
static int send_photo(const void *p,size_t n,int *cleanup_rc) {
    assert(f.opened==1 && f.closed==1 && p!=f.data && n==f.size);
    assert(!memcmp(p,f.reference,n));++f.imports;*cleanup_rc=f.unload_rc;return f.import_rc;
}
static const wb_sftp_ops fs={.ctx=&f,.open=op,.close=cl,.read=rd,.fstat=st};
static wb_out sink={&f,write_reply};
static void *no_mem(size_t n) { (void)n;return NULL; }
static uint8_t *file(const char *path,size_t *n) {
    FILE *in=fopen(path,"rb");assert(in && !fseek(in,0,SEEK_END));
    long size=ftell(in);assert(size>0 && (unsigned long)size<=WB_VITA_PHOTO_MAX_BYTES);*n=(size_t)size;
    rewind(in);uint8_t *data=malloc(*n);assert(data && fread(data,1,*n,in)==*n);
    assert(!fclose(in));return data;
}
static void img(const uint8_t *raw,size_t n,const char *leaf) {
    free(f.data);free(f.reference);memset(&f,0,sizeof f);
    f.data=malloc(n);f.reference=malloc(n);assert(f.data&&f.reference);
    memcpy(f.data,raw,n);memcpy(f.reference,raw,n);
    f.length=f.size=n;snprintf(f.want,sizeof f.want,"/%s",leaf);
}
static void gate(const char *p,const char *sha,const char *want,int opens,int calls,void *(*a)(size_t)) {
    int status=-1,cleanup=0;
    int rc=wb_photo_export_command(p,sha,&sink,&status,&fs,send_photo,a,&cleanup);
    assert(!rc && f.opened==opens && f.closed==(!f.openfx&&opens) && f.imports==calls);
    assert(status==(want!=NULL) && cleanup==(calls?f.unload_rc:0));
    char good[200];snprintf(good,sizeof good,"OK photo-export bytes=%lu sha256=%s\n",(unsigned long)f.size,sha);
    if (strcmp(f.reply,want?want:good)) { fprintf(stderr,"unexpected: %s",f.reply);exit(1); }
    ++cases;
}
static void parse(const char *line,int valid) {
    wb_cmd c;int ok=wb_cmd_parse(line,strlen(line),&c);
    assert(ok==valid);
    if (ok) assert(c.kind==WB_CMD_PHOTO_EXPORT && !strcmp(wb_cmd_name(c.kind),"photo-export"));
    ++cases;
}
int main(int argc,char **argv) {
    assert(argc==5);
    size_t jn,pn;uint8_t *jpg=file(argv[1],&jn),*png=file(argv[3],&pn);
    char *jh=argv[2],*ph=argv[4];
    parse("photo-export " P "x.jpg " FAKE_SHA,1);
    parse("photo-export " P "x.jpg " FAKE_SHA " --install",0);
    parse("photo-export " P "x.jpg sha256=" FAKE_SHA,0);
    parse("photo-export " P "x.jpg " FAKE_SHA " sha256=" FAKE_SHA,0);
    parse("photo-export " P "x.jpg " FAKE_SHA " extra",0);
    parse("photo-export " P "x.jpg FFFF",0);
    parse("photo-export",0);
    assert(strstr(wb_cmd_help_text(),"  photo-export <"));
    const char *deny[]={"ux0:data/x.jpg","UX0:/VITA-POC/x.jpg",P "../x.jpg",P "a/b.jpg",P "a\\b.jpg",
        P ".jpg",P "a.b.jpg",P "a.jpg.",P "a.bmp",P "a b.jpg",P "a.jpg:",P "a$.jpg"};
    for (size_t i=0;i<sizeof deny/sizeof deny[0];i++) {
        img(jpg,jn,"x.jpg");gate(deny[i],jh,"ERR photo-path-or-extension\n",0,0,malloc);
    }
#define J() img(jpg,jn,"x.jpg")
#define G(err,opens,imports) gate(P "x.jpg",jh,err,opens,imports,malloc)
    J();gate(P "x.jpg","123","ERR photo-digest\n",0,0,malloc);
    J();f.mutate=1;G(NULL,1,1); /* underlying file changed after close; import saw original snapshot */
    J();f.unload_rc=-1;G(NULL,1,1);
    img(jpg,jn,"A_9-t.JpEg");gate(P "A_9-t.JpEg",jh,NULL,1,1,malloc);
    img(png,pn,"x.PNG");gate(P "x.PNG",ph,NULL,1,1,malloc);
    J();f.openfx=WB_SFTP_NO_FILE;G("ERR photo-not-found\n",1,0);
    J();f.openfx=WB_SFTP_DENIED;G("ERR photo-open\n",1,0);
    J();f.statfx=WB_SFTP_FAILURE;G("ERR photo-stat\n",1,0);
    J();f.dir=1;G("ERR photo-stat\n",1,0);
    J();f.length=0;G("ERR photo-size\n",1,0);
    J();f.length=(uint64_t)WB_VITA_PHOTO_MAX_BYTES+1;G("ERR photo-size\n",1,0);
    J();f.length=WB_VITA_PHOTO_MAX_BYTES;gate(P "x.jpg",jh,"ERR nomem\n",1,0,no_mem);
    J();f.truncate=1;G("ERR photo-read\n",1,0);
    J();f.grow=1;G("ERR photo-read\n",1,0);
    J();f.readfx=WB_SFTP_FAILURE;G("ERR photo-read\n",1,0);
    J();f.closefx=WB_SFTP_FAILURE;G("ERR photo-close\n",1,0);
    J();f.data[f.size-1]=0;G("ERR photo-format\n",1,0);
    J();f.data[0]=0;G("ERR photo-format\n",1,0);
    J();f.data[4]^=1;G("ERR photo-hash-mismatch\n",1,0);
    img(png,pn,"x.jpg");gate(P "x.jpg",ph,"ERR photo-format\n",1,0,malloc);
    img(jpg,jn,"x.png");gate(P "x.png",jh,"ERR photo-format\n",1,0,malloc);
    img(png,pn,"x.png");memset(f.data+16,0,4);gate(P "x.png",ph,"ERR photo-format\n",1,0,malloc);
    img(png,pn,"x.png");f.data[pn-1]=0;gate(P "x.png",ph,"ERR photo-format\n",1,0,malloc);
    J();f.import_rc=-17;G("ERR photo-export rc=0xffffffef\n",1,1);
    free(jpg);free(png);free(f.data);free(f.reference);
    printf("PASS %d photo parser/gate cases; JPEG+PNG, snapshot hash, library errors and cleanup\n",cases);
    return 0;
}
