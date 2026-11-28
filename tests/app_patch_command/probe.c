#include <stdio.h>
#include <string.h>
#include "wb_shell.h"
#include "wb_patch_auth.h"
static int count;
static int wr(void *x,const char *p,size_t n){(void)x; return fwrite(p,1,n,stdout)==n?0:-1;}
static int core(void *x,const wb_cmd *c,wb_out *o){
    (void)x;(void)o;
    if(c->kind==WB_CMD_TERM_APP_PATCH){count++;printf("PATCH %d %s\n",c->argc,c->argv[0]);}
    return 0;
}
int main(int n,char **v){
    if(n==4 && !strcmp(v[1],"message")){
        char m[WB_PATCH_MESSAGE_CAP];if(!wb_patch_message(m,v[2],v[3]))return 3;fputs(m,stdout);return 0;
    }
    if(n!=2)return 4;
    wb_shell_ops ops={0};ops.core_exec=core;wb_out o={NULL,wr};
    wb_cmd cmd;if(wb_cmd_parse(v[1],strlen(v[1]),&cmd)&&cmd.kind==WB_CMD_TERM_APP_PATCH)return 5;
    wb_shell_engine sh;wb_shell_init(&sh);wb_shell_run(&sh,v[1],&o,&ops);
    return count==1 && wb_shell_streamed_app(v[1])?0:2;
}
