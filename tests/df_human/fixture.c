#include "wb_shell.h"
#include "wb_df_human.h"
#include <assert.h>
#include <string.h>
static char buf[1024];static size_t len;static int calls,legacy,api;
static uint64_t cap,free_bytes;
static int sink(void *x,const char *s,size_t n){(void)x;assert(len+n<sizeof buf);memcpy(buf+len,s,n);buf[len+=n]=0;return 0;}
static int core(void *x,const wb_cmd *c,wb_out *out){
    (void)x;if(c->kind==WB_CMD_TERM_DF_HUMAN){assert(!c->argc);++calls;return wb_df_human(out,api,cap,free_bytes);}
    if(c->kind==WB_CMD_DF)++legacy;
    return 0;
}
static void command(const char *cmd){
    wb_shell_engine sh;wb_shell_init(&sh);wb_shell_ops ops={0};ops.core_exec=core;
    wb_out out={NULL,sink};buf[0]=0;len=0;calls=legacy=0;
    (void)wb_shell_run(&sh,cmd,&out,&ops);
}
int main(void){
    cap=80ULL<<30;free_bytes=15ULL<<30;
    command("df -h");assert(calls==1&&!legacy&&strstr(buf,"80.0 GiB")&&strstr(buf,"65.0 GiB")&&strstr(buf,"15.0 GiB")&&strstr(buf,"82%")&&strstr(buf,"ux0:/"));puts(buf);
    cap=UINT64_MAX;free_bytes=cap;command("df -h");assert(strstr(buf,"15.9 EiB")&&strstr(buf," 0%"));
    free_bytes=cap-1;command("df -h");assert(strstr(buf," 1%"));
    free_bytes=0;command("df -h");assert(strstr(buf,"100%"));
    cap=10;free_bytes=11;command("df -h");assert(strstr(buf,"ERR space-unavailable")&&!strstr(buf,"Mounted"));
    cap=free_bytes=0;command("df -h");assert(strstr(buf,"ERR"));
    cap=500;api=-1;command("df -h");assert(strstr(buf,"api=0xFFFFFFFF")&&!strstr(buf,"Mounted"));api=0;
    command("df -h ur0:/");assert(!calls&&!legacy&&strstr(buf,"ERR usage:"));
    command("df");assert(legacy==1&&!calls);command("df 98765");assert(legacy==1&&!calls);
    wb_cmd c={0};const char *raw="df -h";assert(!wb_cmd_parse(raw,strlen(raw),&c)||c.kind!=WB_CMD_TERM_DF_HUMAN);
    char unit[WB_DF_FIELD];wb_df_units(unit,1023);assert(!strcmp(unit,"1023 B"));
    wb_df_units(unit,1024);assert(!strcmp(unit,"1.0 KiB"));wb_df_units(unit,1536);assert(!strcmp(unit,"1.5 KiB"));
    puts("PASS scoped df -h, IEC boundaries, 64-bit and error paths, legacy df unchanged.");return 0;
}
