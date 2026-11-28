/* Regression for synchronous App progress through the real shell/editor.
 * Fake read/write endpoints only: no SSH, Vita or remote commands. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_shell_channel.h"
#include "wb_screen_mirror.h"

#define CAP 524288u
#define LINES 3000u
static wb_shell_channel shell;
static struct {
    const char *input;
    size_t offset,size,rdcap,wrcap,nwire,nmirror;
    unsigned reads,writes,core_writes,cores,apps,vers,statuses,commands,mirror_begins;
    bool in_core,core_returned,aborted;
    int fail_mode;
    char wire[CAP],mirror[CAP];
} test;
void wb_mirror_begin(void){test.mirror_begins++;test.nmirror=0;}
void wb_mirror_geometry(unsigned cols,unsigned rows){assert(cols==80 && rows==24);}
void wb_mirror_write(const uint8_t *bytes,size_t n){
    assert(test.nmirror+n<CAP);memcpy(test.mirror+test.nmirror,bytes,n);test.nmirror+=n;test.mirror[test.nmirror]=0;
}
static int input(void *ctx,uint8_t *bytes,size_t n){
    (void)ctx;assert(!test.in_core);test.reads++;
    if(test.offset==test.size)return -2;
    if(n>test.size-test.offset)n=test.size-test.offset;
    if(n>test.rdcap)n=test.rdcap;
    memcpy(bytes,test.input+test.offset,n);test.offset+=n;return (int)n;
}
static int output(void *ctx,const uint8_t *bytes,size_t n){
    (void)ctx;test.writes++;
    if(test.in_core){
        test.core_writes++;
        if(test.fail_mode && test.core_writes==5){
            if(test.fail_mode==1)return 0;
            if(test.fail_mode==2)return -1;
            return (int)n+1;
        }
    }
    if(n>test.wrcap)n=test.wrcap;
    assert(test.nwire+n<CAP);memcpy(test.wire+test.nwire,bytes,n);test.nwire+=n;test.wire[test.nwire]=0;
    return (int)n;
}
static int core(void *ctx,const wb_cmd *command,wb_out *out){
    (void)ctx;assert(!test.in_core);test.cores++;
    if(command->kind==WB_CMD_VER){
        assert(test.core_returned);test.vers++;
        return wb_out_puts(out,"VER after-app\n");
    }
    const bool app=command->kind==WB_CMD_APP_INSTALL || command->kind==WB_CMD_TERM_APP_PLAN;
    assert(app || command->kind==WB_CMD_STATUS);
    if(app){test.apps++;assert(command->argc==1 || command->argc==2);}
    else test.statuses++;
    test.in_core=true;const unsigned reads=test.reads;const unsigned cores=test.cores;
    for(unsigned n=0;n<LINES;n++){
        const size_t before=test.nwire;
        int rc=wb_out_printf(out,"app-progress phase=copy bytes=%u\n",n);
        assert(test.reads==reads && test.cores==cores); /* no recursive input/dispatch */
        if(rc<0){test.aborted=true;test.in_core=false;test.core_returned=true;return -1;}
        if(app){
            assert(test.nwire>before && test.core_writes>0); /* observed BEFORE return */
            assert(!test.core_returned && !test.vers);
        }else assert(test.nwire==before); /* ordinary command remains bounded/buffered */
    }
    int rc=wb_out_puts(out,command->kind==WB_CMD_TERM_APP_PLAN?
        "OK app-plan title=LARG12345 app_ver=01.00 action=none\n":
        "OK app-install title=LARG12345 app_ver=01.00 files=303 detail=0 session=kept\n");
    test.in_core=false;test.core_returned=true;return rc;
}
static const wb_shell_ops ops={.core_exec=core};
static int pump(void){unsigned count=0;int rc=wb_sh_pump(&shell,NULL,input,output,&ops,&count);assert(count<=1);test.commands+=count;return rc;}
static void reset(const char *line,size_t rd,size_t wr,int fail){
    memset(&test,0,sizeof test);test.input=line;test.size=strlen(line);test.rdcap=rd;test.wrcap=wr;test.fail_mode=fail;
    assert(!wb_sh_start(&shell,true));wb_sh_set_geometry(&shell,80,24);
}
static int finish(void){
    int rc=1;unsigned ticks=0;
    while(rc>0 && ticks++<200000)rc=pump();
    assert(ticks<200000);
    assert(test.nwire==test.nmirror && !memcmp(test.wire,test.mirror,test.nwire));
    assert(test.mirror_begins==1);return rc;
}
static void all_progress(void){
    const char *position=test.wire;
    for(unsigned n=0;n<LINES;n++){
        char line[80];snprintf(line,sizeof line,"app-progress phase=copy bytes=%u\r\n",n);
        const char *found=strstr(position,line);assert(found);position=found+strlen(line);
    }
    assert(strstr(position,"OK app-") && strstr(position,"VER after-app\r\n"));
    assert(!strstr(test.wire,"ERR output-limit"));
}
static void valid(void){
    static const char *const app[]={
        "app-install ux0:/VITA-POC/game.vpk",
        "  app-install   \"ux0:/VITA-POC/game file.vpk\"  ",
        "'app-install' 'ux0:/VITA-POC/game file.vpk'",
        "app install ux0:/VITA-POC/game.vpk",
        "  'app'  \"install\"  'ux0:/VITA-POC/game file.vpk'  ",
        "app plan ux0:/VITA-POC/game.vpk",
        "\"app\" 'plan' 'ux0:/VITA-POC/game file.vpk' fs-smoke"
    };
    for(unsigned i=0;i<sizeof app/sizeof *app;i++){
        char script[640];snprintf(script,sizeof script,"%s\nver\nexit\n",app[i]);
        assert(wb_shell_streamed_app(app[i]));
        reset(script,i%2?3:256,i%3==0?1:i%3==1?7:4096,0);
        assert(finish()==0 && test.apps==1 && test.vers==1 && test.cores==2 && test.commands==3);
        assert(test.core_writes && test.nwire>65536);all_progress();
    }
    puts("PASS actual wb_sh_pump/core_exec sends 3000 App progress lines (>100KiB) before return, exact ordered OLED mirror, 1/7/4096-byte partial writes, quoted/whitespace install/plan spellings");
}
static void denial(void){
    static const char *const invalid[]={
        "app-install", "app-install ux0:/VITA-POC/game.vpk extra",
        "app install", "app install ux0:/VITA-POC/game.vpk extra",
        "app plan", "app plan ux0:/VITA-POC/game.vpk x extra",
        "app-install ux0:/data/private.vpk", "app-install --force",
        "app plan ux0:/VITA-POC/game.vpk --force",
        "app-install \"\"", "app-install ux0:/VITA-POC/game.vpk;ver",
        "app-install \"ux0:/VITA-POC/bad.vpk", "app plan ux0:/VITA-POC/a.vpk | ver"
    };
    for(unsigned i=0;i<sizeof invalid/sizeof *invalid;i++){
        char script[640];snprintf(script,sizeof script,"%s\nexit\n",invalid[i]);
        reset(script,256,7,0);assert(finish()==0 && !test.cores && strstr(test.wire,"ERR "));
    }
    assert(wb_shell_streamed_app("\t'app'\tinstall\t'ux0:/VITA-POC/game file.vpk'\t"));
    assert(!wb_shell_streamed_app("app list"));assert(!wb_shell_streamed_app("status"));
    assert(!wb_shell_streamed_app("app-install a;b"));assert(!wb_shell_streamed_app("app plan a b c"));
    char too_long[WB_SH_LINE+2];memset(too_long,'a',sizeof too_long-1);too_long[sizeof too_long-1]=0;
    assert(!wb_shell_streamed_app(too_long));
    puts("PASS output classifier is not authorization: actual parser still rejects invalid paths, flags, counts, quotes and shell syntax before any core dispatch");
}
static void failure(void){
    for(int mode=1;mode<=3;mode++){
        reset("app-install ux0:/VITA-POC/game.vpk\nver\nexit\n",256,7,mode);
        assert(finish()==-1 && test.apps==1 && test.cores==1 && !test.vers && test.aborted);
        assert(!strstr(test.wire,"OK app-install") && !strstr(test.wire,"VER after-app"));
        assert(test.core_writes==5 && test.reads==1);
    }
    puts("PASS zero-progress/error/oversize writers fail closed during synchronous App execution: no success receipt, spin, inbound read or later queued command dispatch");
}
static void ordinary(void){
    reset("status\nver\nexit\n",256,7,0);
    assert(finish()==0 && test.statuses==1 && test.vers==1 && test.cores==2 && test.commands==3);
    assert(test.aborted && !test.core_writes && strstr(test.wire,"ERR output-limit\r\n"));
    assert(!strstr(test.wire,"app-progress") && strstr(test.wire,"VER after-app\r\n"));
    puts("PASS ordinary command retains 24KiB bounded-output rejection and next-command usability; App drain does not turn the editor into a recursive input pump");
}
int main(void){valid();denial();failure();ordinary();return 0;}
