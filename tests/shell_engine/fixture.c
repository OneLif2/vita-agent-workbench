#include "wb_shell.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,listed,cded,catted,executed;
static int lng,err_sink;
static char reply[4096],last[WB_SH_PATH];
static wb_shell_engine s,s2;
static wb_cmd last_cmd;
static int fail(int line,const char *assertion){fprintf(stderr,"FAIL line %d: %s; reply=%s\n",line,assertion,reply);exit(1);return 0;}
#define CHECK(a) (++checks,(a)?0:fail(__LINE__,#a))
static int wr(void *ctx,const char *p,size_t n){
    (void)ctx;if(err_sink)return -1;
    if(n>=sizeof reply-strlen(reply))return -1;
    size_t z=strlen(reply);memcpy(reply+z,p,n);reply[z+n]=0;return 0;
}
static int exists(void *ctx,const char *p,wb_out *o){
    (void)ctx;cded++;snprintf(last,sizeof last,"%s",p);
    if(!strcmp(p,"ux0:/")||!strcmp(p,"ux0:/VITA-POC")||!strcmp(p,"ux0:/VITA-POC/Some Folder")||
       !strcmp(p,"ux0:/data")||!strcmp(p,"ux0:/uncommon/-folder"))return 0;
    return wb_out_puts(o,"ERR not a visible directory\n")<0?-1:1;
}
static int ls(void *ctx,const char *p,bool l,wb_out *o){
    (void)o;(void)ctx;lng=l;listed++;snprintf(last,sizeof last,"%s",p);return 0;
}
static int cat(void *ctx,const char *p,wb_out *o){
    (void)o;(void)ctx;catted++;snprintf(last,sizeof last,"%s",p);return 0;
}
static int core(void *ctx,const wb_cmd *c,wb_out *o){
    (void)ctx;executed++;last_cmd=*c;
    return wb_out_puts(o,"text\033[32m\033]payload\a\r\n");
}
static wb_out out={NULL,wr};
static wb_shell_ops ops={NULL,exists,ls,cat,core};
static int issue(wb_shell_engine *sh,const char *input){reply[0]=0;return wb_shell_run(sh,input,&out,&ops);}
static void cmd(const char *input){CHECK(issue(&s,input)==0);}
static void deny(const char *input){
    unsigned old=executed+listed+cded+catted;cmd(input);
    CHECK(!strncmp(reply,"ERR ",4));CHECK(executed+listed+cded+catted==old);
}
int main(void){
    wb_shell_init(&s);wb_shell_init(&s2);CHECK(!strcmp(s.cwd,"ux0:/"));
    wb_shell_prompt(&s,&out);CHECK(!strcmp(reply,"ux0:/> "));
    cmd("pwd");CHECK(!strcmp(reply,"ux0:/\n"));
    cmd("ls -l");CHECK(lng&&!strcmp(last,"ux0:/"));
    cmd("cd VITA-POC");CHECK(!strcmp(s.cwd,"ux0:/VITA-POC")&&!strcmp(s2.cwd,"ux0:/"));
    cmd("ls .");CHECK(!lng&&!strcmp(last,"ux0:/VITA-POC"));
    cmd("cd \"Some Folder\"");CHECK(!strcmp(s.cwd,"ux0:/VITA-POC/Some Folder"));
    cmd("cat '../hello world.txt'");CHECK(!strcmp(last,"ux0:/VITA-POC/hello world.txt"));
    cmd("ls -l /data");CHECK(lng&&!strcmp(last,"ux0:/data"));
    cmd("cat ./hello.txt");CHECK(!strcmp(last,"ux0:/VITA-POC/Some Folder/hello.txt"));
    cmd("cd missing");CHECK(strstr(reply,"ERR")&&!strcmp(s.cwd,"ux0:/VITA-POC/Some Folder"));
    cmd("cd ../../../../..");CHECK(!strcmp(s.cwd,"ux0:/"));
    cmd("cd ..");CHECK(!strcmp(s.cwd,"ux0:/"));
    cmd("cd ux0:data");CHECK(!strcmp(s.cwd,"ux0:/data"));
    cmd("ls -l ux0:/VITA-POC/");CHECK(!strcmp(last,"ux0:/VITA-POC")&&lng);
    cmd("cd");CHECK(!strcmp(s.cwd,"ux0:/"));
    cmd("ls -- -x");CHECK(!strcmp(last,"ux0:/-x"));
    cmd("cat -- -l");CHECK(!strcmp(last,"ux0:/-l"));
    deny("ls -R");deny("ls -la");deny("cat");deny("cd extra args");deny("ls -l 'a");deny("cat ux0://file");
    deny("cd ur0:/");deny("cd ux0:dataX");deny("cat a:b");deny("cat a\\b");deny("pwd\nexit");
    deny("ls ; exit");deny("ls && pwd");deny("cat /a|wc");deny("cd \"\"");deny("cd 'x. '");
    deny("cat test?");deny("ls > x");deny("ls\033");deny("ls \xc3\xa9");
    cmd("  \t ");CHECK(!*reply);
    char big[560];memset(big,'z',sizeof big);big[sizeof big-1]=0;deny(big);
    memset(big,'z',400);big[400]=0;memcpy(big,"ls ",3);deny(big);
    cmd("help");CHECK(strstr(reply,"help transfer")&&strstr(reply,"pwd"));
    cmd("help transfer");CHECK(strstr(reply,"sha256=HEX")&&!strstr(reply,"SFTP"));
    cmd("help app");CHECK(strstr(reply,"app plan VPK"));
    cmd("help test");CHECK(strstr(reply,"test result CASE JOB"));
    cmd("help update");CHECK(strstr(reply,"r1-status"));
    cmd("help files");CHECK(strstr(reply,"empty directory"));
    cmd("help status");CHECK(strstr(reply,"hash-selftest"));
    deny("help anything");deny("help update anything");
    deny("bash");deny("scp -t file");deny("ext missing");deny("exit more");
    deny("send C:\\temp\\file");CHECK(strstr(reply,"framed SSH terminal"));
    deny("put file 1 sha256=hash");deny("get file");
    cmd("ver");CHECK(last_cmd.kind==WB_CMD_VER);CHECK(!strcmp(reply,"text?[32m?]payload?\n"));
    cmd("ext hello");CHECK(last_cmd.kind==WB_CMD_EXT && !strcmp(last_cmd.argv[0],"hello"));
    cmd("status");CHECK(last_cmd.kind==WB_CMD_STATUS);cmd("df 400");CHECK(!strcmp(last_cmd.argv[0],"400"));
    cmd("cd VITA-POC");cmd("inspect 'a b.vpk'");CHECK(last_cmd.kind==WB_CMD_INSPECT&&!strcmp(last_cmd.argv[0],"ux0:/VITA-POC/a b.vpk"));
    unsigned e=executed;cmd("doctor");CHECK(executed==e+5 && last_cmd.kind==WB_CMD_TIMELINE);deny("doctor reboot");
    cmd("app list");CHECK(last_cmd.kind==WB_CMD_TERM_APP_LIST&&!last_cmd.argc);
    cmd("app plan 'game app.vpk' fs-smoke");CHECK(last_cmd.kind==WB_CMD_TERM_APP_PLAN&&last_cmd.argc==2&&!strcmp(last_cmd.argv[0],"ux0:/VITA-POC/game app.vpk"));
    cmd("app install 'game app.vpk'");CHECK(last_cmd.kind==WB_CMD_APP_INSTALL&&last_cmd.argc==1);
    cmd("update plan wb.vpk");CHECK(last_cmd.kind==WB_CMD_PLAN);
    cmd("update stage wb.vpk sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");CHECK(last_cmd.kind==WB_CMD_INSTALL&&strlen(last_cmd.sha256)==64);
    CHECK(last_cmd.no_reload);
    cmd("deploy allowed.suprx");CHECK(last_cmd.kind==WB_CMD_TERM_DEPLOY);
    deny("deploy ux0:data/INAP00018/x");deny("app plan ux0:data/INAP00018/x");
    deny("inspect ux0:data/INAP00018/private-info");deny("plan ux0:data/INAP00018/private-info");
    cmd("inspect ux0:data/INAP00018/shot.bmp");CHECK(last_cmd.kind==WB_CMD_INSPECT);
    cmd("update apply");CHECK(last_cmd.kind==WB_CMD_APPLY_CORE && !last_cmd.argc);
    cmd("test run fs-smoke A_123");CHECK(last_cmd.kind==WB_CMD_LAUNCH&&!strcmp(last_cmd.argv[0],"INAP00020")&&!strcmp(last_cmd.argv[2],"A_123"));
    cmd("test result fs-smoke A_123");CHECK(last_cmd.kind==WB_CMD_TERM_RESULT&&!strcmp(last_cmd.argv[0],"fs-smoke")&&!strcmp(last_cmd.argv[1],"A_123"));
    deny("app install x --any-title");deny("app list extra");deny("app plan");deny("app plan --force");deny("test run x '../job'");deny("test result A");deny("update stage wb.vpk --force");deny("update apply extra");deny("df -1");
    cmd("plan a.vpk");CHECK(!strcmp(last_cmd.argv[0],"ux0:/VITA-POC/a.vpk"));
    cmd("app-install a.vpk");CHECK(last_cmd.kind==WB_CMD_APP_INSTALL);
    cmd("ext ls ..");CHECK(!strcmp(last,"ux0:/"));
    cmd("ext stat ux0:/data/public.txt");CHECK(!strcmp(last_cmd.argv[1],"ux0:data/public.txt"));
    cmd("mkdir 'plot A'");CHECK(!strcmp(last_cmd.argv[0],"ux0:/VITA-POC/plot A"));
    cmd("ext mv example.txt moving.txt");CHECK(!strcmp(last_cmd.argv[1],"ux0:/VITA-POC/example.txt")&&!strcmp(last_cmd.argv[2],"ux0:/VITA-POC/moving.txt"));
    deny("ext mv f ../outside");deny("ext rm .");deny("rm ux0:data/INAP00018/x");deny("ext tick --force");
    deny("install update.vpk");deny("install update.vpk --any-title");deny("app-install");deny("plan file extra");deny("ver --force");
    cmd("install update.vpk sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --no-reload");
    CHECK(last_cmd.kind==WB_CMD_INSTALL && last_cmd.no_reload && strlen(last_cmd.sha256)==64);
    deny("apply-return invalid");cmd("apply-return 11111111111111111111111111111111");
    CHECK(last_cmd.kind==WB_CMD_APPLY_RETURN);
    cmd("photo-export p.jpg 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(last_cmd.kind==WB_CMD_PHOTO_EXPORT && !strcmp(last_cmd.argv[0],"ux0:/VITA-POC/p.jpg"));
    CHECK(issue(&s,"exit")==1&&!strcmp(reply,"Bye.\n"));CHECK(!strcmp(s2.cwd,"ux0:/"));
    err_sink=1;CHECK(wb_shell_prompt(&s,&out)<0);CHECK(issue(&s,"pwd")<0);
    CHECK(issue(&s,"exit")<0);CHECK(issue(&s,"ver")<0);
    printf("PASS %u assertions: session cwd, paths, quotes, root, read-only builtins, guarded core forwarding, transfer guidance and exit\n",checks);
    return 0;
}
