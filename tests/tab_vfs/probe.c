/* End-to-end Tab -> real shell resolver + real Vita VFS, with only the
 * handheld's directory calls mocked by the existing independent VFS fixture. */
#define main run_existing_vfs_tests
#include "../shell_vfs/fixture.c"
#undef main
#include "wb_shell.h"

static const wb_shell_ops real={NULL,wb_vita_shell_isdir,wb_vita_shell_list,wb_vita_shell_cat,NULL};
static wb_shell_engine sh;
static void test(const char *prefix,const char *expect){
    char edited[WB_SH_LINE];memset(edited,0,sizeof edited);
    int roots=diropens,files=fileopens;
    bool success=wb_shell_complete(&sh,prefix,&real,edited);
    if(success!=(expect!=NULL) || (expect && strcmp(edited,expect))){
        fprintf(stderr,"Tab(%s): expected=%s, actual=%s\n",prefix,expect?expect:"(none)",success?edited:"(none)");abort();
    }
    if(expect && !strchr(prefix,' '))assert(roots==diropens);
    assert(files==fileopens);done();
}
int main(void){
    wb_shell_init(&sh);test("pw","pwd ");test("cd /d","cd /data/");test("cd /in","cd /inbox/");
    test("cat /inbox/tw","cat \"/inbox/two words.txt\"");test("ls -l /inbox/s","ls -l /inbox/sub/");
    test("ls /inbox/sub/pl","ls /inbox/sub/plain.txt");test("cd /inbox/sub/p",NULL);
    test("cat /data/INAP00018/ru","cat /data/INAP00018/run.log");
    const char *denied[]={"cd /ta","cd /app","cd /data/acc","ls /data/INAP00018/se",
       "cat /data/INAP00018/peer","cat /data/INAP00018/HOST","cat /data/INAP00018/time",
       "ls /inbox/link","ls /inbox/link/pri","ls /inbox/sub/sub.link/p","ls /inbox/.hi",
       "ls /inbox/ba","ls /inbox/negative","ls /inbox/../data/r","ls /inbox/../../d",
       "ls /Vita-Poc/sub/p","ls vit0:/d","ls /data/INAP00018/./ho"};
    for(size_t i=0;i<sizeof denied/sizeof *denied;i++)test(denied[i],NULL);
    symlink_root=1;test("cd /in",NULL);test("cat /inbox/sub/pl",NULL);symlink_root=0;
    dirfail=1;test("cd /da",NULL);dirfail=0;
    forceclose=1;test("ls /inbox/sub/pl",NULL);forceclose=0;
    huge=1;int before=dreads;test("ls /inbox/abc",NULL);assert(dreads-before<550);huge=0;
    fullscan=1;before=dreads;test("ls /inbox/sub/pl",NULL);assert(dreads-before<550);fullscan=0;
    toolong=1;test("ls /inbox/sub/pl",NULL);toolong=0;
    assert(!fileopens && !rawcat);printf("PASS %u real Tab -> Vita VFS cases: public paths only, symlink/hidden/private/type/alias checks, clean EOF required, bounded scans; no file reads or command execution.\n",(unsigned)matches);
}
