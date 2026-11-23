/* Host-only ABI receiver. Validates address representations without following
 * any value supplied by the core. No Vita, filesystem or network functions. */
#include <stdio.h>
#include <string.h>
#include "wb_cmd.h"
#include "wb_ver.h"
#include "wb_payload.h"
#include "wb_str.h"
#include "wb_ext_path_policy.h"
static struct {char payload_ver[32];} a;
static int g_ssh, calls, first, count, lazy, loads, ok, usage, denied;
static const wb_cmd *expected;
static wb_out *expected_out;
static int sink(void *unused,const char *bytes,size_t size){
    (void)unused;
    const char *e="ERR usage: ext <cmd>\n";
    usage=(size==strlen(e) && memcmp(bytes,e,size)==0);
    const char *d="ERR path-denied\n";
    denied=(size==strlen(d) && memcmp(bytes,d,size)==0);
    return 0;
}
static int receiver(const char *cmd,int argc,char *const argv[],wb_out *out,void *core){
    calls++;
    ok=(cmd==(first?expected->argv[0]:expected->name) && argc==count && out==expected_out && core==&g_ssh);
    if(argc==count && count>0){
        /* For the original row matrix these bytes are accessible as object
         * representation, not valid pointer objects. Never evaluate argv[i]. */
        const unsigned char *slots=(const unsigned char *)(const void *)argv;
        for(int i=0;i<count;i++){
            const char *wanted=expected->argv[first+i];
            if(memcmp(slots+(size_t)i*sizeof(char *),&wanted,sizeof wanted)!=0)ok=0;
        }
    }
    return 23; /* distinguish payload return from core or sink return */
}
static const wb_payload_v1 table={WB_PAYLOAD_MAGIC,WB_PAYLOAD_ABI,sizeof(wb_payload_v1),"fixture","host","",receiver};
static const wb_payload_v1 *wb_vita_payload_table(void){return lazy?NULL:&table;}
static void startup_mark(const char *ignored,int code){(void)ignored;(void)code;}
static int wb_vita_payload_boot(char *ver,size_t cap){loads++;lazy=0;wb_strcpy(ver,cap,table.version);return 0;}
static const char *wb_err_name(int ignored){(void)ignored;return "fixture";}
static int route(const wb_cmd *cmd,wb_out *out,int *status){
    switch(cmd->kind){
#include "ext_path.inc"
        default:return -99;
    }
}
static int check(const char *label,const char *line,int offset,int nargs,int load,int is_usage){
    wb_cmd parsed;wb_out o={NULL,sink};
    first=offset;count=nargs;lazy=load;calls=loads=usage=ok=denied=0;expected_out=&o;expected=&parsed;
    int passed=wb_cmd_parse(line,strlen(line),&parsed) && parsed.kind==WB_CMD_EXT;
    if(passed){
        int status=0,ret=route(&parsed,&o,&status);
        passed=is_usage==2?(denied && status!=0 && !calls && !loads && ret==0):
               is_usage?(usage && !calls && !loads && ret==0):
               (ok && !usage && !denied && status==0 && calls==1 && loads==load && ret==23);
    }
    printf("%s %s\n",passed?"PASS":"FAIL",label);
    return passed;
}
int main(void){
    int n=0;char max_token[137]="ext echo ";memset(max_token+9,'x',127);max_token[136]=0;
    n+=check("explicit-zero-operands","ext hello",1,0,0,0);
    n+=check("shorthand-zero-operands","hello",0,0,0,0);
    n+=check("explicit-one-operand","ext ls ux0:data",1,1,0,0);
    n+=check("shorthand-one-operand","ls ux0:/VITA-POC/",0,1,0,0);
    n+=check("explicit-two-operands","ext check sample beta",1,2,0,0);
    n+=check("explicit-all-five-operands","ext check one two three four five",1,5,0,0);
    n+=check("shorthand-all-six-operands","check one two three four five six",0,6,0,0);
    n+=check("explicit-max-token",max_token,1,1,0,0);
    n+=check("explicit-lazy-load","ext stat ux0:/app/INAP00018",1,1,1,0);
    n+=check("shorthand-lazy-load","stat ux0:data/sample",0,1,1,0);
    n+=check("bare-ext-rejected","ext",0,0,0,1);
    const char *valid[]={"rm ux0:data/INAP00018/sample","mkdir ux0:/VITA-POC/tmp",
                         "ext mv ux0:/VITA-POC/from ux0:data/INAP00018/to","ext stat ux0:data/dir/"};
    n+=check("valid-rm",valid[0],0,1,1,0);
    n+=check("valid-mkdir",valid[1],0,1,1,0);
    n+=check("valid-mv",valid[2],1,2,1,0);
    n+=check("valid-trailing-dir",valid[3],1,1,1,0);
    const char *bad[]={"rm ux0:data/sample","ext mv ux0:/VITA-POC/from ux0:data/to","mkdir ux0:data/INAP00019/not-writable","ls savedata0:","ext ls ur0:/data","stat relative","ext stat ux0:dataX",
        "rm ux0:/VITA-POC/../denied","ext rm ux0:data/./item","mkdir ux0:data//b",
        "ext mkdir ux0:data/a:b","ext stat ux0:data/a\\b","mv ux0:data/../b ux0:data/y",
        "ext mv ux0:data/x savedata0:/y","mv ux0:/app/INAP00018/x ux0:data/y",
        "rm ux0:data","mkdir ux0:/VITA-POC/","ext ls ux0:/app//","stat ux0:data/trailing.",
        "ext mv ux0:data/only","ext ls ux0:data extra"};
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);i++)
        n+=check(bad[i],bad[i],0,0,1,2);
    int total=15+(int)(sizeof(bad)/sizeof(*bad));
    printf("RESULT %d/%d passed\n",n,total);
    return n==total?0:1;
}
