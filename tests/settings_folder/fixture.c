/* Compile the actual PTY shell. No filesystem, network or button adapter. */
#include "wb_shell.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static char wire[4096];
static size_t used;
static const char *queue,*file;
static int calls,core_error;
static int record(void *unused,const char *p,size_t n){
 (void)unused;assert(used+n<sizeof wire);memcpy(wire+used,p,n);used+=n;wire[used]=0;return 0;
}
static int read_only(void *ctx,const wb_cmd *c,wb_out *out){
 (void)ctx;++calls;const char *s;
 if(calls==1){
  assert(c->kind==WB_CMD_PENDING && c->argc==0);s=queue;
 }else{
  assert(calls==2 && c->kind==WB_CMD_EXT && !strcmp(c->name,"ext") && c->argc==2);
  assert(!strcmp(c->argv[0],"stat") && !strcmp(c->argv[1],"ux0:/app/INAP00019/eboot.bin"));s=file;
 }
 if(calls==core_error)return 1;
 /* Exercise split receive calls, including empty/oversized malformed replies. */
 size_t n=strlen(s);
 if(n>1 && out->write(out->ctx,s,1)<0)return -1;
 return out->write(out->ctx,s+(n>1),n-(n>1));
}
static void test(const char *cmd,const char *want,int count){
 wb_shell_engine sh;wb_shell_init(&sh);wb_out o={NULL,record};wb_shell_ops ops={.core_exec=read_only};
 calls=0;used=0;wire[0]=0;assert(!wb_shell_run(&sh,cmd,&o,&ops));
 assert(strstr(wire,want)!=NULL && calls==count && !strcmp(sh.cwd,"ux0:/"));
}
int main(void){
 const char *command="settings updater-folder";
 queue="pending-core: no\n";file="F ux0:/app/INAP00019/eboot.bin 161418\n";
 for(int i=0;i<3;++i)test(command,"updater-file=present layout=unverified",2);
 test("help","help settings",0);test("help settings","Never edits LiveArea",0);test("settings","settings updater-folder",0);
 test("settings updater-folder --apply","ERR usage",0);test("settings move INAP00018","ERR usage",0);
 test("settings updater-folder ; rm xyz","ERR",0);
 core_error=1;test(command,"WAIT",1);core_error=2;test(command,"UNVERIFIED",2);core_error=0;
 const char *noq[]={"pending-core: WBQ2 abc\n","ERR IO\n","pending-core: no\nextra\n",""};
 for(size_t i=0;i<sizeof noq/sizeof *noq;i++){queue=noq[i];test(command,"WAIT",1);}
 queue="pending-core: no\n";
 const char *badf[]={"ERR not-found\n","D ux0:/app/INAP00019/eboot.bin\n","F ux0:/app/INAP00020/eboot.bin 161418\n","F ux0:/app/INAP00019/eboot.bin 0\n","F ux0:/app/INAP00019/eboot.bin 7x\n","F ux0:/app/INAP00019/eboot.bin 2\nOK\n","F ux0:/app/INAP00019/eboot.bin 12345678901\n",""};
 for(size_t i=0;i<sizeof badf/sizeof *badf;i++){file=badf[i];test(command,"UNVERIFIED",2);}
 char oversize[194];memset(oversize,'a',193);oversize[193]=0;queue=oversize;test(command,"WAIT",1);
 puts("PASS: settings updater-folder actual PTY dispatch: 24 read-only cases; queued, unknown, file mismatch, invalid args refused; no layout or button operation.");return 0;
}
