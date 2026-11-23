/* Offline directory stream fixture. The only Vita I/O symbols linked into
 * this test binary are directory open/read/close. No files may be opened. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wb_shell.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
static int oom;
static void *try_calloc(size_t n,size_t w){return oom?NULL:calloc(n,w);}
#define calloc try_calloc
#include "wb_crash_index.h"
#undef calloc
enum { MODE_B_KEY=2 };
struct fake_conn {
    int authenticated;
    struct {int accepted,mode;} mode;
    int session,channel,shell,shell_pty,sftp_ro;
};
static struct fake_conn g_ssh;
static SceIoDirent entries[1025];
static unsigned total,idx,opens,closes,reads;
static int open_fail,read_fail,close_fail,dispatch_status,fail_write;
static char capture[12000]; static size_t used;
static void reset(void){
    memset(entries,0,sizeof entries);
    total=idx=opens=closes=reads=0;
    used=0;capture[0]=0;
    oom=open_fail=close_fail=fail_write=0;read_fail=-1;dispatch_status=-1;
    g_ssh=(struct fake_conn){1,{1,MODE_B_KEY},1,1,1,1,0};
}
static void add(const char *n,SceMode mode,SceOff size,unsigned year,unsigned month,unsigned day){
    CHECK(total<1025&&strlen(n)<256);
    SceIoDirent *e=entries+total++;strcpy(e->d_name,n);e->d_stat.st_size=size;e->d_stat.st_mode=mode;
    e->d_stat.st_mtime=(SceDateTime){year,month,day,20,30,40,0};
}
SceUID sceIoDopen(const char *dir){CHECK(!strcmp(dir,"ux0:data"));++opens;return open_fail?-1:73;}
int sceIoDread(SceUID fd,SceIoDirent *e){
    SceIoDirent zero={0};CHECK(fd==73&&memcmp(e,&zero,sizeof zero)==0);
    ++reads;if((int)idx==read_fail)return -1;
    if(idx==total)return 0;
    *e=entries[idx++];return 1;
}
int sceIoDclose(SceUID fd){CHECK(fd==73);++closes;return close_fail?-1:0;}
static int collect(void *ctx,const char *p,size_t n){
    (void)ctx;if(fail_write)return -1;
    CHECK(used+n<sizeof capture);memcpy(capture+used,p,n);used+=n;capture[used]=0;return 0;
}
static int adapter(const wb_cmd *cmd,wb_out *out,int *status){
    switch(cmd->kind){
#include "dispatch_under_test.inc"
    default:*status=1;return wb_out_puts(out,"ERR unexpected descriptor\n");
    }
}
static int core(void *ctx,const wb_cmd *cmd,wb_out *out){
    (void)ctx;int rc=adapter(cmd,out,&dispatch_status);return rc<0?rc:dispatch_status;
}
static int run(const char *line){
    wb_shell_engine sh;wb_shell_init(&sh);
    wb_shell_ops ops={0};ops.core_exec=core;wb_out out={NULL,collect};
    return wb_shell_run(&sh,line,&out,&ops);
}
static const char head[]="OK crash-index matched=0 shown=0 truncated=0 clock=device-local\nEND crash-index\n";
static void expect(const char *line,const char *s){
    CHECK(run(line)==0);if(strcmp(capture,s)){fprintf(stderr,"actual: %s\n",capture);CHECK(0);}
}
static void example(void){
    add("psp2core-fake-eboot.bin.tmp",0x2000,4294967297LL,2026,11,21);
    add("unrelated.log",0x2000,154,2026,11,22);
}
int main(int argc,char **argv){
    reset();
    if(argc==2){example();int rc=run(argv[1]);fputs(capture,stdout);return rc<0?2:rc;}
    expect("diag crashes",head);CHECK(opens==1&&reads==1&&closes==1&&dispatch_status==0);puts("PASS empty vs failure");
    reset();example();
    add("psp2core-Dir",0x1000,0,2027,1,1);add("psp2core-Link",0x4000,1,2027,1,1);
    add("psp2core-b.tmp",0x2000,0,2026,11,21);add("psp2core-a.tmp",0x2000,1,2026,11,21);
    add("psp2core-Z",0x2000,2,2026,11,22);add("psp2core-unknown",0x2000,9,2025,2,29);
    expect("diag crashes --limit 3","OK crash-index matched=5 shown=3 truncated=1 clock=device-local\n"
        "crash name=psp2core-Z modified=2026-11-22T20:30:40 bytes=2\n"
        "crash name=psp2core-a.tmp modified=2026-11-21T20:30:40 bytes=1\n"
        "crash name=psp2core-b.tmp modified=2026-11-21T20:30:40 bytes=0\nEND crash-index\n");
    puts("PASS top-k by newest civil second and deterministic name; regular files only");
    reset();example();add("psp2core-bad-date",0x2000,2,2100,2,29);add("psp2core-leap",0x2000,1,2000,2,29);
    CHECK(run("diag crashes")==0&&strstr(capture,"bytes=4294967297\n")&&strstr(capture,"2000-02-29T20:30:40 bytes=1\ncrash name=psp2core-bad-date modified=unknown bytes=2\nEND"));
    puts("PASS 64-bit extent, civil date validation, unknown last without invented timezone");
    reset();const char *ignored[]={"psp2core-","PSP2CORE-a.tmp","psp2core-_foo","psp2core-foo.","psp2core-x..y","psp2core-a/b","psp2core-a\\b",
        "psp2core-a\033z","psp2core-a\nz","psp2core-a b","private.log"};
    for(unsigned i=0;i<sizeof ignored/sizeof *ignored;i++)add(ignored[i],0x2000,1,2000,1,1);
    add("psp2core-too-long",0x2000,0,2000,1,1);memset(entries[total-1].d_name+9,'a',170);
    add("psp2core-unterminated",0x2000,0,2000,1,1);memset(entries[total-1].d_name+9,'z',247);
    expect("diag crashes",head);puts("PASS basename/control/traversal/nonterminated-name exclusion");
    const char *bad[]={"diag","diag dump","diag crashes --limit","diag crashes /","diag crashes --limit 0","diag crashes --limit 33","diag crashes --limit 01",
                      "diag crashes --limit -1","diag crashes --limit 99999","diag crashes --path ux0:data","diag crashes --limit 1 extra"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){reset();expect(bad[i],"ERR crash-index usage\n");CHECK(!opens);}
    reset();CHECK(run("diag crashes | cat")==0&&strstr(capture,"ERR syntax")&&!opens);
    puts("PASS canonical syntax, no supplied path or expansions");
    for(int i=0;i<8;i++){
        reset();int *fields[]={&g_ssh.authenticated,&g_ssh.mode.accepted,&g_ssh.mode.mode,&g_ssh.session,&g_ssh.channel,&g_ssh.shell,&g_ssh.shell_pty,&g_ssh.sftp_ro};
        *fields[i]=(i==7);expect("diag crashes","ERR crash-index no-pty\n");CHECK(!opens&&dispatch_status==1);
    }
    reset();wb_cmd parsed;
    CHECK(!wb_cmd_parse("diag crashes",12,&parsed)||parsed.kind!=WB_CMD_TERM_CRASH_INDEX);
    CHECK(!wb_cmd_parse("crash-index",11,&parsed)||parsed.kind!=WB_CMD_TERM_CRASH_INDEX);
    puts("PASS each negotiated state gate and no raw-exec parser route");
    reset();oom=1;expect("diag crashes","ERR crash-index nomem\n");CHECK(!opens&&!closes&&dispatch_status==1);
    reset();open_fail=1;expect("diag crashes","ERR crash-index open\n");CHECK(opens==1&&!closes);
    reset();example();read_fail=1;expect("diag crashes","ERR crash-index read\n");CHECK(closes==1);
    reset();example();close_fail=1;expect("diag crashes","ERR crash-index close\n");
    reset();example();add("psp2core-neg",0x2000,-1,2000,1,1);expect("diag crashes","ERR crash-index metadata\n");CHECK(closes==1);
    reset();example();fail_write=1;CHECK(run("diag crashes")<0&&closes==1&&dispatch_status==1);
    puts("PASS no false empty/partial success on memory/open/mid-read/close/invalid-size/output faults");
    reset();for(int i=0;i<1024;i++){char n[32];snprintf(n,sizeof n,"psp2core-%04d",1024-i);add(n,0x2000,i,2026,1,1);}
    CHECK(run("diag crashes --limit 32")==0&&strstr(capture,"matched=1024 shown=32 truncated=1")&&strstr(capture,"psp2core-0032")&&!strstr(capture,"psp2core-0033")&&reads==1025);
    reset();for(int i=0;i<1014;i++)add("unrelated",0x2000,0,0,0,0);for(int i=0;i<11;i++)add("psp2core-file",0x2000,0,2000,1,1);
    expect("diag crashes","ERR crash-index scan-limit\n");CHECK(reads==1025&&closes==1);
    puts("PASS exact 1024 scan boundary; overflow suppresses all rows; max 32 retained");
    reset();for(int i=0;i<11;i++){char n[32];snprintf(n,sizeof n,"psp2core-%d",i);add(n,0x2000,0,2000,1,1);}
    CHECK(run("diag crashes")==0&&strstr(capture,"matched=11 shown=10 truncated=1"));puts("PASS default limit 10");
    return 0;
}
