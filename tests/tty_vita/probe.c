/* Data-only filesystem fault injection; production adapter/digest/path functions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "wb_cmd.h"
#include "wb_ver.h"
#include "wb_tty_file.h"
#include "wb_path.h"
#include "wb_out.h"
#include "wb_checked_hash.h"
#include "wb_sftp_vita.h"
#include "../../wake-probe/wake_probe_protocol.h"
typedef int SceIoStat;typedef size_t SceSize;typedef int64_t SceOff;
typedef struct {int fd;} wb_vfile;
enum {SCE_SEEK_SET=0,SCE_SEEK_END=2,SCE_O_RDONLY=1};
static struct {char run_hex[17];} a={"1234567890abcdef"};
#ifndef WB_TEST_FS_CAP
#define WB_TEST_FS_CAP 256
#endif
static struct F {char name[128];uint8_t b[WB_TEST_FS_CAP];size_t n,pos;int isdir;} fs[24];
static int replacing,shortage,damage,io_writes,io_removes;
/* Test-only syscall faults; armed only after the private file is open. */
static int inject_write,inject_step,inject_close,inject_remove,inject_sync;
static int find(const char *p){for(int i=1;i<24;i++)if(!strcmp(fs[i].name,p))return i;return -1;}
static int make(const char *p){int i=find(p);if(i<0){for(i=1;i<24;i++)if(!*fs[i].name)break;}assert(i<24);memset(&fs[i],0,sizeof fs[i]);strcpy(fs[i].name,p);return i;}
static int sceIoGetstat(const char *p,SceIoStat *s){(void)s;return find(p)<0?(int)0x80010002:0;}
static int sceIoOpen(const char *p,int flags,int mode){(void)flags;(void)mode;int f=find(p);if(f>=0)fs[f].pos=0;return f;}
static int sceIoClose(int f){return inject_close?inject_close:f>0?0:-1;}
static int sceIoMkdir(const char *p,int mode){(void)mode;if(find(p)>=0)return (int)0x80010011;fs[make(p)].isdir=1;return 0;}
static int sceIoSyncByFd(int f,int flag){(void)flag;if(damage)fs[f].b[0]^=1;return inject_sync;}
static int sceIoRead(int f,void *b,size_t n){if(n>fs[f].n-fs[f].pos)n=fs[f].n-fs[f].pos;memcpy(b,fs[f].b+fs[f].pos,n);fs[f].pos+=n;return (int)n;}
static int sceIoWrite(int f,const void *b,size_t n){++io_writes;
    if(inject_write==1){if(inject_step++)return (int)0x80010005u;if(n>2)n=2;}
    if(inject_write==2)return 0;
    if(inject_write==3)return (int)n+1;
    if(inject_write==4&&n>1)n=1;
    assert(fs[f].pos+n<=sizeof fs[f].b);memcpy(fs[f].b+fs[f].pos,b,n);fs[f].pos+=n;fs[f].n=fs[f].pos;return (int)n;}
static SceOff sceIoLseek(int f,SceOff n,int whence){fs[f].pos=(size_t)(whence==SCE_SEEK_END?(SceOff)fs[f].n+n:n);return (SceOff)fs[f].pos;}
static int sceIoRemove(const char *p){++io_removes;if(inject_remove)return inject_remove;int f=find(p);if(f<0)return -1;memset(&fs[f],0,sizeof fs[f]);return 0;}
static int sceIoRename(const char *a,const char *b){int f=find(a),q=find(b);if(f<0)return -1;if(q>0){if(!replacing)return (int)0x80010011;sceIoRemove(b);}strcpy(fs[f].name,b);return 0;}
static int open_staging(const char *p,int *rc){(void)rc;return make(p);}
static int wb_vita_read_small(const char *p,void *b,size_t cap,size_t *n){int f=sceIoOpen(p,1,0);if(f<0)return -1;*n=(size_t)sceIoRead(f,b,cap);return 0;}
static int wb_vita_mkdir_p(const char *p){(void)p;return 0;}
static int wb_ux0_budget(uint64_t n,wb_out *out,bool show){(void)n;(void)out;(void)show;return shortage?WB_E_LIMIT:WB_OK;}
/* Mirror 02.11 write_upload_chunk for dual-version comparison of the same
 * adapter fixture. 02.12 reads the raw syscall return instead. */
static inline int write_upload_chunk(int f,const uint8_t *p,size_t n){
    for(size_t off=0;off<n;){int k=sceIoWrite(f,p+off,n-off);if(k<=0||(size_t)k>n-off)return WB_E_IO;off+=(size_t)k;}
    return WB_OK;
}
static int ra(const void *ctx,uint64_t off,void *dst,size_t n){int f=((wb_vfile *)ctx)->fd;sceIoLseek(f,(SceOff)off,0);return sceIoRead(f,dst,n)==(int)n?WB_OK:WB_E_IO;}
static int wb_vita_reader_open(const char *p,wb_reader *r,wb_vfile *f){f->fd=find(p);if(f->fd<0)return -1;r->ctx=f;r->size=fs[f->fd].n;r->read_at=ra;return 0;}
static void wb_vita_reader_close(wb_vfile *f){f->fd=-1;}
int wb_sftp_name_ok(const char *p,size_t n){(void)n;return wb_path_name_ok(p);}
static int st(void *c,const char *p,wb_sftp_attr *a){
    (void)c;if(!strcmp(p,"/")){a->is_dir=1;return WB_SFTP_OK;}
    char key[160];snprintf(key,sizeof key,WB_INCOMING "%s",p);int f=find(key);
    if(f<0)return WB_SFTP_NO_FILE;
    a->is_dir=fs[f].isdir;return WB_SFTP_OK;
}
static int op(void *c,const char *p,int dir,int *f){(void)c;(void)dir;char path[150];snprintf(path,sizeof path,WB_INCOMING "%s",p);*f=sceIoOpen(path,1,0);return *f<0?2:0;}
const wb_sftp_ops wb_sftp_vita_ops={.stat=st,.open=op};
#ifndef WB_TEST_GAME_LOG_API_CUSTOM
/* Legacy transfer fixtures grant no new game-log access. The dedicated
 * game_logs_tty fixture injects its own checked-read API contract. */
int wb_vita_shell_open_game_log(const char *p,int *fd){(void)p;if(fd)*fd=-1;return -1;}
#endif
#include "wb_tty_vita.inc"
static int private_count(void){int n=0;for(int i=1;i<24;i++)n+=strstr(fs[i].name,"/tty-")!=NULL;return n;}
static int result_read_cli(void){
    const char *path=WP_RESULT_PATH;
    int f=make(WB_ROOT "/wake-probe/result.bin");
    for(unsigned i=0;i<256;i++)fs[f].b[i]=(uint8_t)i;
    fs[f].n=256;io_writes=io_removes=0;
    void *h=NULL;uint64_t size=0;const char*error=wb_tty_vopen(false,path,0,&h,&size);
    if(error){printf("DENIED error=%s writes=%d removes=%d\n",error,io_writes,io_removes);return 0;}
    uint8_t bytes[256],digest[32];size_t got=0;assert(size==256);
    assert(!wb_tty_vread(h,bytes,sizeof bytes,&got)&&got==256);
    assert(!wb_tty_vfinish(h,true,NULL));
    wb_sha256 hash;wb_sha256_init(&hash);wb_sha256_update(&hash,bytes,got);wb_sha256_final(&hash,digest);char sum[65];wb_sha_hex(digest,32,sum);
    printf("GET bytes=%llu read=%zu sha256=%s readonly=1 writes=%d removes=%d\n",(unsigned long long)size,got,sum,io_writes,io_removes);return 0;
}
int main(int argc,char**argv){ (void)&wb_s2_selftest;
    if(argc==2&&!strcmp(argv[1],"get-result"))return result_read_cli();
    void *h=NULL;uint64_t n;const char *p=WB_INCOMING "/unit.bin";
    const uint8_t abc[]="abc";
    const char *sha="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert(wb_tty_vopen(true,"ux0:/data/INAP00018/run.log",3,&h,&n)&&!h);
    assert(wb_tty_vopen(true,WB_INCOMING "/../bad",3,&h,&n)&&!h);
    assert(wb_tty_vopen(false,"ux0:/data/INAP00018/mac-public-pin.txt",0,&h,&n)&&!h);
    assert(wb_tty_vopen(false,"ux0:/data/INAP00018/testapp/../secret",0,&h,&n)&&!h);
    shortage=1;assert(!strcmp(wb_tty_vopen(true,p,3,&h,&n),"no-space"));shortage=0;
    replacing=1;assert(!strcmp(wb_tty_vopen(true,p,3,&h,&n),"no-clobber-unavailable"));replacing=0;assert(!private_count());
    /* Boundary-only mock metadata, not a claim of actual multi-GiB transfer. */
    assert(!wb_tty_vopen(true,p,UINT64_C(201326593),&h,&n)&&n==UINT64_C(201326593));
    assert(!wb_tty_vfinish(h,false,NULL)&&!private_count());
    assert(!wb_tty_vopen(true,p,WB_TRANSFER_MAX,&h,&n)&&n==WB_TRANSFER_MAX);
    assert(!wb_tty_vfinish(h,false,NULL)&&!private_count());
    assert(!strcmp(wb_tty_vopen(true,p,WB_TRANSFER_MAX+1u,&h,&n),"bad-size")&&!h);
    puts("PASS native PUT metadata: removed192MiB quota, uint32 maximum admitted, uint32+1 refused before create (no huge payload)");

    assert(!wb_tty_vopen(true,p,3,&h,&n)&&n==3);
    assert(!wb_tty_vwrite(h,abc,3)&&!wb_tty_vfinish(h,false,NULL)&&!private_count()&&find(p)<0);
    assert(!wb_tty_vopen(true,p,3,&h,&n));assert(!wb_tty_vwrite(h,abc,3));damage=1;
    assert(!strcmp(wb_tty_vfinish(h,true,sha),"stage-hash-mismatch")&&!private_count()&&find(p)<0);damage=0;
    assert(!wb_tty_vopen(true,p,3,&h,&n));assert(!wb_tty_vwrite(h,abc,3));
    int other=make(p);sceIoWrite(other,"KEEP",4);
    assert(wb_tty_vfinish(h,true,sha)&&!memcmp(fs[other].b,"KEEP",4)&&!private_count());sceIoRemove(p);
    assert(!wb_tty_vopen(true,p,3,&h,&n));assert(!wb_tty_vwrite(h,abc,3));assert(!wb_tty_vfinish(h,true,sha)&&!private_count());
    assert(wb_tty_vopen(true,p,3,&h,&n)&&!h);
    uint8_t buf[8];size_t got;assert(!wb_tty_vopen(false,p,0,&h,&n)&&n==3);assert(!wb_tty_vread(h,buf,sizeof buf,&got)&&got==3&&!memcmp(buf,abc,3));assert(!wb_tty_vfinish(h,true,sha));
    make(WB_ROOT "/testapp/result.txt");assert(!wb_tty_vopen(false,"ux0:/data/INAP00018/testapp/result.txt",0,&h,&n)&&n==0);assert(!wb_tty_vfinish(h,true,NULL));
    const char *k=NULL,*dir=WB_INCOMING "/from 5090",*child=WB_INCOMING "/from 5090/empty.txt";
    assert(!wb_tty_vprobe(WB_INCOMING,&k)&&!strcmp(k,"DIR"));
    assert(!wb_tty_vprobe(dir,&k)&&!strcmp(k,"ABSENT"));
    assert(wb_tty_vopen_stream(child,&h)&&!h);
    assert(!wb_tty_vmkdir(dir)&&wb_tty_vmkdir(dir));
    assert(!wb_tty_vprobe(dir,&k)&&!strcmp(k,"DIR"));
    assert(!wb_tty_vopen_stream(child,&h));
    assert(!wb_tty_vfinish(h,true,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert(!wb_tty_vprobe(child,&k)&&!strcmp(k,"FILE"));
    assert(wb_tty_vmkdir(WB_INCOMING "/from 5090/empty.txt/child"));
    assert(wb_tty_vmkdir(WB_INCOMING "/../outside")&&wb_tty_vmkdir(WB_INCOMING "/trailing."));
    assert(!wb_tty_vopen_stream(WB_INCOMING "/stream.bin",&h));shortage=1;
    assert(!strcmp(wb_tty_vwrite(h,abc,3),"no-space"));shortage=0;
    assert(!wb_tty_vwrite(h,abc,3)&&!wb_tty_vfinish(h,true,sha));
    assert(!wb_tty_vopen_stream(WB_INCOMING "/from 5090/no.bin",&h));
    assert(!wb_tty_vwrite(h,abc,3));fs[find(dir)].isdir=0;
    assert(!strcmp(wb_tty_vfinish(h,true,sha),"path-denied")&&!private_count());
    /* Exact public result only: no normalization/prefix expansion, no private
     * pending/claim/job file, and no write/tree capability added. */
    const char *result=WP_RESULT_PATH;
    int result_fd=make(WB_ROOT "/wake-probe/result.bin");
    for(unsigned i=0;i<256;i++)fs[result_fd].b[i]=(uint8_t)i;
    fs[result_fd].n=256;int writes_before=io_writes,removes_before=io_removes;
    uint8_t result_bytes[256];size_t result_got=0;
    assert(!wb_tty_vopen(false,result,0,&h,&n)&&n==256);
    assert(!wb_tty_vread(h,result_bytes,sizeof result_bytes,&result_got)&&result_got==256);
    assert(wb_tty_vwrite(h,abc,1));
    assert(!wb_tty_vfinish(h,true,NULL));
    assert(!memcmp(result_bytes,fs[result_fd].b,256));
    assert(io_writes==writes_before&&io_removes==removes_before);
    assert(wb_tty_vopen(true,result,256,&h,&n)&&!h);
    assert(wb_tty_vopen_stream(result,&h)&&!h);
    assert(wb_tty_vmkdir(result)&&wb_tty_vmkdir("ux0:/data/INAP00018/wake-probe"));
    assert(wb_tty_vprobe(result,&k)&&wb_tty_vprobe("ux0:/data/INAP00018/wake-probe",&k));
    const char *denied[]={
      "ux0:/data/INAP00018/wake-probe/job.bin",
      "ux0:/data/INAP00018/wake-probe/result.bin.new",
      "ux0:/data/INAP00018/wake-probe/result.bin/child",
      "ux0:/data/INAP00018/wake-probe/../result.bin",
      "ux0:/data/INAP00018/wake-probe/./result.bin",
      "ux0:/data/INAP00018/wake-probe//result.bin",
      "ux0:/data/INAP00018/wake-probe/RESULT.bin",
      "ux0:/data/INAP00018/wake-probe/private.bin",
      "ux0:/data/INAP00018/wake-probe/result.bin/../../mac-public-pin.txt",
      "ux0:/data/INAP00018/wb-wake-probe-v1.bin",
      "savedata0:/wb-wake-probe-v1.bin",
      "savedata0:/wake-probe-claim.bin",
      "ux0:data/INAP00018/wake-probe/result.bin"};
    for(unsigned i=0;i<sizeof denied/sizeof *denied;i++){
        assert(wb_tty_vopen(false,denied[i],0,&h,&n)&&!h);
        assert(wb_tty_vopen(true,denied[i],256,&h,&n)&&!h);
        assert(wb_tty_vopen_stream(denied[i],&h)&&!h);
        assert(wb_tty_vmkdir(denied[i]));
        assert(wb_tty_vprobe(denied[i],&k));
    }
    /* Closing/aborting a read handle cannot unlink or alter the public file. */
    assert(!wb_tty_vopen(false,result,0,&h,&n));assert(!wb_tty_vfinish(h,false,NULL));
    assert(find(WB_ROOT "/wake-probe/result.bin")==result_fd&&fs[result_fd].n==256);
    assert(io_writes==writes_before&&io_removes==removes_before);
    puts("PASS exact wake-probe/result.bin GET only: 256-byte read, readonly handle, 13 job/private/sibling/traversal negatives x5 operations, tree/mkdir/PUT/stream denied and no unlink/write");
    puts("PASS tree and stream: canonical parents, no-merge mkdir, empty file, shortage, verified streaming SHA and replaced parent refused");
    puts("PASS native adapter: no-space, path scope, no-clobber capability, destination race, abort cleanup, corrupt readback, verified publish, bounded incoming/diagnostic reads (mock Vita filesystem)");
    return 0;
}
