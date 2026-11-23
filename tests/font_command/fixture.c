#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "wb_ver.h"
#include "wb_shell.h"
#include "wb_screen_mirror.h"
#include "wb_font_command.h"
#define SCE_O_RDONLY 1
#define SCE_O_WRONLY 2
#define SCE_O_CREAT 4
#define SCE_O_TRUNC 8
struct memfile {uint8_t data[WB_FONT_REC+1];unsigned n,pos;int open,write,exists;};
static struct memfile slots[2];
static int nwrite,failbyte=-1,badsync;
static int idx(const char*p){if(!strcmp(p,WB_ROOT "/font-a.cfg"))return 0;assert(!strcmp(p,WB_ROOT "/font-b.cfg"));return 1;}
static int sceIoOpen(const char*p,int flags,int mode){int i=idx(p);struct memfile*f=&slots[i];assert(!f->open);
 if(flags==SCE_O_RDONLY){assert(!mode);if(!f->exists)return -1;f->write=0;}
 else {assert(flags==(SCE_O_WRONLY|SCE_O_TRUNC|SCE_O_CREAT)&&mode==0600);f->write=f->exists=1;f->n=0;nwrite++;}
 f->open=1;f->pos=0;return i;
}
static int sceIoClose(int fd){assert(slots[fd].open);slots[fd].open=0;return 0;}
static int sceIoRead(int fd,void*out,unsigned want){struct memfile*f=&slots[fd];assert(f->open&&!f->write);
 unsigned n=f->n-f->pos;if(n>want)n=want;if(n>3)n=3;memcpy(out,f->data+f->pos,n);f->pos+=n;return (int)n;}
static int sceIoWrite(int fd,const void*src,unsigned want){struct memfile*f=&slots[fd];assert(f->open&&f->write);
 if(failbyte>=0&&(int)f->pos>=failbyte)return -1;
 unsigned n=want>3?3:want;
 assert(f->pos+n<=sizeof f->data);memcpy(f->data+f->pos,src,n);f->n=f->pos+=n;return (int)n;}
static int sceIoSyncByFd(int fd,int flags){assert(slots[fd].open&&slots[fd].write&&!flags);return badsync?-1:0;}
#include "font_adapter.inc"
static char buf[65536];static size_t used;static wb_shell_engine sh;
static int emit(void*c,const char*p,size_t n){(void)c;assert(used+n+1<sizeof buf);memcpy(buf+used,p,n);used+=n;buf[used]=0;return 0;}
static int core(void*c,const wb_cmd*cmd,wb_out*out){(void)c;int stat=0;assert(cmd->kind==WB_CMD_TERM_FONT);
 assert(wb_font_command(cmd,out,&stat,&font_state,&font_storage)==0);return stat;}
static wb_out sink={NULL,emit};static const wb_shell_ops ops={.core_exec=core};
static void run(const char*cmd,const char*expected){
 used=0;buf[0]=0;assert(wb_shell_run(&sh,cmd,&sink,&ops)==0);if(!strstr(buf,expected)){fprintf(stderr,"%s -> %s; expected %s\n",cmd,buf,expected);assert(0);}
}
static void boot(void){wb_font_boot(&font_state,&font_storage);wb_shell_init(&sh);}
int main(void){
 wb_mirror_begin();wb_mirror_geometry(132,40);boot();
 run("font","font family=classic scale=2 gap_x=2 gap_y=6 cols=80 rows=22");
 run("help","help font");run("help font","Saved across app restarts.");
 char completed[WB_SH_LINE];assert(wb_shell_complete(&sh,"fon",&ops,completed)&&!strcmp(completed,"font "));
 run("font reset","gap_y=6");assert(!nwrite);
 run("font license","SIL OPEN FONT LICENSE");assert(!strcmp(buf,wb_jb_license)&&strlen(buf)>4000&&!nwrite);
 const char*bad[]={"font set bad 1 2 2","font set classic 0 2 6","font set classic 4 2 6",
 "font set classic -1 2 6","font set classic +2 2 6","font set classic 2 5 6","font set classic 2 2 1",
 "font set classic 2 2 11","font set classic 2 2 01","font set classic 2 x 2","font set classic 2 2",
 "font reset junk","font set classic 2 2 6;df","font set classic 2 2 6 extra","font ../file","font set ux0:/foo 2 2 6"};
 for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){run(bad[i],"ERR ");assert(!nwrite&&wb_fsame(wb_type_get(),WB_TYPE_DEFAULT));}
 wb_cmd raw;assert(!wb_cmd_parse("font",4,&raw)||raw.kind!=WB_CMD_TERM_FONT);
 run("font set classic 2 2 8","font family=classic scale=2 gap_x=2 gap_y=8");assert(nwrite==1);
 run("font set classic 2 2 8","gap_y=8");assert(nwrite==1);
 boot();run("font","gap_y=8");assert(font_state.slot==0&&font_state.generation==1);
 run("font set jetbrains 1 4 10","family=jetbrains scale=1 gap_x=4 gap_y=10");assert(nwrite==2);
 wb_shell_init(&sh);run("font","family=jetbrains");boot();run("font","gap_y=10");
 assert(font_state.slot==1&&font_state.generation==2);
 for(int faults=0;faults<4;faults++){
   struct memfile good=slots[1];
   if(faults==0)slots[1].n--;          /* torn newest */
   if(faults==1)slots[1].data[12]^=3; /* checksum mismatch */
   if(faults==2)slots[1].n++;          /* trailing bytes */
   if(faults==3){slots[1].data[9]=255;wb_fput32(slots[1].data+12,wb_fsum(slots[1].data));}
   boot();run("font","gap_y=8");assert(font_state.generation==1);slots[1]=good;
 }
 boot();failbyte=5;run("font reset","ERR font-store");assert(wb_type_get().gap_y==10);
 boot();run("font","family=jetbrains");failbyte=-1;badsync=1;run("font reset","ERR font-store");assert(wb_type_get().gap_y==10);badsync=0;
 run("font reset","family=classic scale=2 gap_x=2 gap_y=6");boot();run("font","gap_y=6");
 assert(wb_mirror_cols()==132&&wb_mirror_rows()==40);
 memset(slots[0].data,0,sizeof slots[0].data);memset(slots[1].data,0,sizeof slots[1].data);boot();
 assert(font_state.generation==0&&wb_fsame(wb_type_get(),WB_TYPE_DEFAULT));
 puts("PASS: typed interactive font help/show/set/reset/license and Tab; 16 invalid inputs reject without writes; 132x40 PTY unchanged.");
 puts("PASS: two-slot bounded native IO, short reads/writes, same-value no write, reopen, torn/checksum/trailing/range fallback, sync/write errors, default recovery.");
 return 0;
}
