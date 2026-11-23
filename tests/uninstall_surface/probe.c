/* The callback is a counter, not a promoter implementation or device operation. */
#include "wb_shell.h"
#include <stdio.h>
#include <string.h>
static unsigned calls;
static int sink(void *ctx,const char *s,size_t n){(void)ctx;return fwrite(s,1,n,stdout)==n?0:-1;}
static int core(void *ctx,const wb_cmd *c,wb_out *out){
    (void)ctx;++calls;return wb_out_printf(out,"PROBE core_dispatch argc=%d\n",c->argc);
}
int main(void){
    const char *const inputs[]={"app uninstall VSSH00001","app uninstall INAP00018","app uninstall VSSH00001 extra","app uninstall ux0:/app/VSSH00001","app uninstall VSSH00002"};
    wb_shell_engine sh;wb_shell_init(&sh);wb_out out={NULL,sink};wb_shell_ops ops={0};ops.core_exec=core;
    for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++){unsigned a=calls;puts(inputs[i]);int state=wb_shell_run(&sh,inputs[i],&out,&ops);
       printf("dispatches=%u shell_rc=%d\n",calls-a,state);if(state!=0)return 2;}
    return 0;
}
