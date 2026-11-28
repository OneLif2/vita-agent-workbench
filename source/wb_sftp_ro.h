#ifndef WB_SFTP_RO_H
#define WB_SFTP_RO_H
#include <stddef.h>
#include <stdint.h>

/* SFTP v3 message bodies. Four-byte transport framing belongs to the caller. */
enum { WB_SFTP_PACKET_MAX=65536, WB_SFTP_DATA_MAX=32768,
       WB_SFTP_REPLY_MAX=WB_SFTP_DATA_MAX+64, WB_SFTP_PATH_MAX=192,
       WB_SFTP_NAME_MAX=100, WB_SFTP_HANDLES=8 };
enum { WB_SFTP_OK=0, WB_SFTP_EOF=1, WB_SFTP_NO_FILE=2, WB_SFTP_DENIED=3,
       WB_SFTP_FAILURE=4, WB_SFTP_BAD_MESSAGE=5, WB_SFTP_UNSUPPORTED=8 };
typedef struct { uint64_t size; uint32_t mtime; int is_dir; } wb_sftp_attr;
/* Return SFTP status codes, not native handles or byte counts. Paths have
 * already been canonicalized into the incoming-only virtual filesystem. */
typedef struct {
    void *ctx;
    int (*stat)(void*,const char*,wb_sftp_attr*);
    int (*open)(void*,const char*,int is_dir,int *fd);
    int (*close)(void*,int fd,int is_dir);
    int (*read)(void*,int fd,uint64_t off,uint8_t *buf,size_t cap,size_t *got);
    int (*readdir)(void*,int fd,char *name,size_t name_cap,wb_sftp_attr*);
    int (*fstat)(void*,int fd,int is_dir,wb_sftp_attr*);
} wb_sftp_ops;
/* Optional create-only backend. finish always releases the writer, including abort. */
typedef struct {
    void *ctx;
    int (*open)(void*,const char*,void**);
    int (*write)(void*,void*,const uint8_t*,size_t);
    int (*finish)(void*,void*,int commit);
    int (*mkdir)(void*,const char*);
} wb_sftp_write_ops;
typedef struct { int fd,dir,used,poison; uint32_t serial; void *writer; uint64_t offset,total; } wb_sftp_handle;
typedef struct {
    const wb_sftp_ops *ops;
    const wb_sftp_write_ops *create;
    int initialized;
    uint32_t last_serial;
    wb_sftp_handle handles[WB_SFTP_HANDLES];
} wb_sftp_ro;

int wb_sftp_name_ok(const char*,size_t);
void wb_sftp_init(wb_sftp_ro*,const wb_sftp_ops*);
void wb_sftp_enable_write(wb_sftp_ro*,const wb_sftp_write_ops*);
void wb_sftp_reset(wb_sftp_ro*);
/* A nonzero result means the channel must be torn down (then call reset).
 * Input and output buffers must not alias. */
int wb_sftp_reply(wb_sftp_ro*,const uint8_t*,size_t,uint8_t*,size_t,size_t*);
#endif
