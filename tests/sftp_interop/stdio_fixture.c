/* OpenSSH -D delegate. Only virtual fixed fixture files; no Vita calls, no
 * host filesystem access, no socket, no shell, no production SSH auth. */
#include "wb_sftp_frame.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define sysread _read
#define syswrite _write
#else
#include <unistd.h>
#define sysread read
#define syswrite write
#endif
typedef struct {const char *path; int parent,dir,size;} item;
static const item nodes[]={
 {"/",-1,1,0},{"/sample",0,1,0},{"/sample/a",1,1,0},
 {"/sample/a/b",2,1,0},{"/sample/a/b/payload.bin",3,0,76543},
 {"/sample/spare",1,1,0},{"/sample/zero.bin",1,0,0},
 {"/sample/top.bin",1,0,17}
};
enum { COUNT=(int)(sizeof nodes/sizeof *nodes) };
static struct {int live,id,next;} fds[WB_SFTP_HANDLES];
static int node(const char *p) {
 for(int i=0;i<COUNT;i++)if(!strcmp(nodes[i].path,p))return i;
 return -1;
}
static int attr(int i,wb_sftp_attr *a) {
 if(i<0||i>=COUNT)return WB_SFTP_NO_FILE;
 *a=(wb_sftp_attr){.size=(uint64_t)nodes[i].size,.mtime=1700000000,.is_dir=nodes[i].dir};
 return WB_SFTP_OK;
}
static int info(void *ctx,const char *p,wb_sftp_attr *a){(void)ctx;return attr(node(p),a);}
static int op(void *ctx,const char *p,int dir,int *fd){
 (void)ctx;int id=node(p);
 if(id<0||nodes[id].dir!=dir)return WB_SFTP_NO_FILE;
 for(int i=0;i<WB_SFTP_HANDLES;i++)if(!fds[i].live){
  fds[i].live=1;fds[i].id=id;fds[i].next=0;*fd=i;return WB_SFTP_OK;
 }
 return WB_SFTP_FAILURE;
}
static int valid(int f,int dir) {
 return f>=0 && f<WB_SFTP_HANDLES && fds[f].live && nodes[fds[f].id].dir==dir;
}
static int details(void *ctx,int f,int dir,wb_sftp_attr *a) {
 (void)ctx;return valid(f,dir)?attr(fds[f].id,a):WB_SFTP_FAILURE;
}
static int cl(void *ctx,int f,int dir) {
 (void)ctx;if(!valid(f,dir))return WB_SFTP_FAILURE;
 fds[f].live=0;return WB_SFTP_OK;
}
static int rd(void *ctx,int f,uint64_t off,uint8_t *b,size_t cap,size_t *got){
 (void)ctx;*got=0;if(!valid(f,0))return WB_SFTP_FAILURE;
 uint64_t size=(uint64_t)nodes[fds[f].id].size;
 if(off>=size)return WB_SFTP_EOF;
 size_t n=(size_t)(size-off);if(n>cap)n=cap;
 for(size_t j=0;j<n;j++)b[j]=(uint8_t)((off+j)%251u);
 *got=n;return WB_SFTP_OK;
}
static int next(void *ctx,int f,char *name,size_t n,wb_sftp_attr *a) {
 (void)ctx;if(!valid(f,1))return WB_SFTP_FAILURE;
 while(fds[f].next<COUNT){
  int i=fds[f].next++;if(nodes[i].parent!=fds[f].id)continue;
  const char *p=strrchr(nodes[i].path,'/')+1;
  if(strlen(p)>=n)return WB_SFTP_FAILURE;
  memcpy(name,p,strlen(p)+1);return attr(i,a);
 }return WB_SFTP_EOF;
}
static int wire_rd(void *ctx,uint8_t *data,size_t cap) {
 (void)ctx;
 int got=(int)sysread(0,data,(unsigned)(cap>259?259:cap));
 return got==0?-2:got;
}
static int wire_wr(void *ctx,const uint8_t *data,size_t n) {
 (void)ctx;return (int)syswrite(1,data,(unsigned)(n>509?509:n));
}
int main(void){
#ifdef _WIN32
 _setmode(0,_O_BINARY);_setmode(1,_O_BINARY);
#endif
 static const wb_sftp_ops fs={NULL,info,op,cl,rd,next,details};
 static wb_sftp_frame f;
 wb_sftp_init(&f.engine,&fs);
 int rc;
 while((rc=wb_sf_pump(&f,NULL,wire_rd,wire_wr))==1){}
 wb_sftp_reset(&f.engine);
 for(int i=0;i<WB_SFTP_HANDLES;i++)if(fds[i].live)return 2;
 return rc?1:0;
}
