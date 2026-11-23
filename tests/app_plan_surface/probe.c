#include "wb_shell.h"
#include <stdio.h>
#include <string.h>
static unsigned count;
static int sink(void *c,const char *s,size_t n){(void)c;(void)s;(void)n;return 0;}
static int probe(void *c,const wb_cmd *cmd,wb_out *out){(void)c;(void)cmd;(void)out;count++;return 0;}
int main(void){
 wb_shell_engine sh;wb_shell_init(&sh);wb_out out={NULL,sink};wb_shell_ops ops={0};ops.core_exec=probe;
 const char *line="app uninstall-plan INAP00020";
 int rc=wb_shell_run(&sh,line,&out,&ops);
 printf("input=%s\nshell_rc=%d core_plan_dispatches=%u platform_delete_calls=0\n",line,rc,count);
 return rc==0&&count<=1?0:2;
}
