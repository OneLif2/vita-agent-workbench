#include "wb_photo_gate.h"
#include "wb_sha256.h"
#include "wb_ver.h"
#include "wb_vita_photo.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

enum imgtype { NO_IMAGE, JPEG, PNG };
static int ext_eq(const char *s,const char *word) {
    while (*word) {
        int c=(unsigned char)*s++;
        if (c>='A' && c<='Z') c += 'a'-'A';
        if (c != *word++) return 0;
    }
    return !*s;
}
static enum imgtype image_type(const char *path) {
    const char prefix[]=WB_INCOMING "/";
    if (!path || strncmp(path,prefix,sizeof prefix-1)) return NO_IMAGE;
    const char *name=path+sizeof prefix-1,*dot=strchr(name,'.');
    if (!dot || dot==name || dot-name>95 || strlen(name)>100) return NO_IMAGE;
    for (const char *p=name;p<dot;p++) {
        char c=*p;
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'))
            return NO_IMAGE;
    }
    if (ext_eq(dot+1,"jpg") || ext_eq(dot+1,"jpeg")) return JPEG;
    return ext_eq(dot+1,"png") ? PNG : NO_IMAGE;
}
static int signature(enum imgtype t,const uint8_t *p,size_t n) {
    if (t==JPEG) return n>=5 && !memcmp(p,"\xff\xd8\xff",3) && !memcmp(p+n-2,"\xff\xd9",2);
    static const uint8_t ihdr[]={137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82};
    static const uint8_t iend[]={0,0,0,0,73,69,78,68,174,66,96,130};
    return t==PNG && n>=45 && !memcmp(p,ihdr,sizeof ihdr) &&
        (p[16]|p[17]|p[18]|p[19]) && (p[20]|p[21]|p[22]|p[23]) &&
        !memcmp(p+n-sizeof iend,iend,sizeof iend);
}

int wb_photo_export_command(const char *path,const char *sha,wb_out *out,int *status,
                            const wb_sftp_ops *fs,wb_photo_import send_photo,
                            void *(*alloc)(size_t),int *cleanup_rc) {
    *status=1; *cleanup_rc=0;
    const enum imgtype type=image_type(path);
    if (!type) return wb_out_puts(out,"ERR photo-path-or-extension\n");
    if (!sha || strlen(sha)!=64 || strspn(sha,"0123456789abcdef")!=64)
        return wb_out_puts(out,"ERR photo-digest\n");
    int fd=-1;
    /* The virtual path starts at '/'; its adapter rejects mount aliases, links,
     * special entries and noncanonical spelling before opening the file. */
    int opened=fs->open(fs->ctx,path+sizeof(WB_INCOMING)-1,0,&fd);
    if (opened!=WB_SFTP_OK || fd<0)
        return wb_out_puts(out,opened==WB_SFTP_NO_FILE?"ERR photo-not-found\n":"ERR photo-open\n");
    wb_sftp_attr a={0};size_t n=0;
    const char *error=NULL;
    uint8_t *image=NULL,probe=0;
    if (fs->fstat(fs->ctx,fd,0,&a)!=WB_SFTP_OK || a.is_dir) error="ERR photo-stat\n";
    else if (!a.size || a.size>WB_VITA_PHOTO_MAX_BYTES) error="ERR photo-size\n";
    else {
        n=(size_t)a.size;
        if (!(image=alloc(n))) error="ERR nomem\n";
    }
    size_t offset=0;
    while (!error && offset<n) {
        size_t request=n-offset,got=0;
        if (request>WB_SFTP_DATA_MAX) request=WB_SFTP_DATA_MAX;
        if (fs->read(fs->ctx,fd,offset,image+offset,request,&got)!=WB_SFTP_OK || !got || got>request)
            error="ERR photo-read\n";
        else offset+=got;
    }
    /* Do not accept a growing file or trust earlier path-based file size. */
    if (!error) {
        size_t got=0;
        if (fs->read(fs->ctx,fd,n,&probe,1,&got)!=WB_SFTP_EOF || got) error="ERR photo-read\n";
    }
    if (fs->close(fs->ctx,fd,0)!=WB_SFTP_OK && !error) error="ERR photo-close\n";
    if (!error && !signature(type,image,n)) error="ERR photo-format\n";
    if (!error) {
        wb_sha256 h; uint8_t d[32]; char digest[65];
        wb_sha256_init(&h); wb_sha256_update(&h,image,n); wb_sha256_final(&h,d); wb_sha_hex(d,32,digest);
        if (strcmp(digest,sha)) error="ERR photo-hash-mismatch\n";
    }
    if (error) { free(image);return wb_out_puts(out,error); }
    /* The platform consumes the exact checked bytes, never a re-opened path. */
    int rc=send_photo(image,n,cleanup_rc);
    free(image);
    if (rc<0) return wb_out_printf(out,"ERR photo-export rc=0x%08" PRIx32 "\n",(uint32_t)rc);
    *status=0;
    return wb_out_printf(out,"OK photo-export bytes=%" PRIu64 " sha256=%s\n",(uint64_t)n,sha);
}
