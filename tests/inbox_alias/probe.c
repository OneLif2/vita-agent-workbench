#include "wb_shell.h"
#include <stdio.h>
#include <string.h>
static int emit(void *u,const char *p,size_t n){(void)u;return fwrite(p,1,n,stdout)==n?0:-1;}
static int dir(void *u,const char *p,wb_out *o){
    (void)u; (void)o;
    if(!strcmp(p,"ux0:/") || !strcmp(p,"ux0:/VITA-POC") || !strcmp(p,"ux0:/VITA-POC/folder one"))return 0;
    return puts("ERR not a visible directory")<0?-1:1;
}
static int ls(void *u,const char *p,bool l,wb_out *o){(void)u;return wb_out_printf(o,"LIST %d %s\n",l?1:0,p);}
static int cat(void *u,const char *p,wb_out *o){(void)u;return wb_out_printf(o,"CAT %s\n",p);}
static int core(void *u,const wb_cmd *c,wb_out *o){
    (void)u;if(wb_out_printf(o,"CORE %s",c->name)<0)return -1;
    for(int i=0;i<c->argc;i++)if(wb_out_printf(o," [%s]",c->argv[i])<0)return -1;
    return wb_out_puts(o,"\n");
}
int main(int argc,char **argv){
    wb_out o={NULL,emit};wb_shell_ops ops={NULL,dir,ls,cat,core};wb_shell_engine s;wb_shell_init(&s);
    for(int i=1;i<argc;i++){if(wb_shell_run(&s,argv[i],&o,&ops)!=0)return 2;}
    return 0;
}
