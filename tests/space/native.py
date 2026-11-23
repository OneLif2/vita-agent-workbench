"""Compile the actual device budget function, with a mocked Vita filesystem query."""
import subprocess,tempfile,os
from pathlib import Path
r=Path(__file__).resolve().parents[2]/'source';source=(r/'vita_ssh_status.c').read_text();start=source.index('static int wb_ux0_budget(');end=source.index('static int do_put(',start)
pre='''#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#define WB_E_IO -1
#define WB_E_LIMIT -2
#define WB_OK 0
typedef struct { char txt[256]; } wb_out;
static int api;
static uint64_t cap,avail;
static int sceAppMgrGetDevInfo(const char *dev, uint64_t *t,uint64_t *a) { assert(!strcmp(dev,"ux0:")); *t=cap;*a=avail;return api; }
static int wb_out_printf(wb_out *o,const char *fmt,...) {va_list ap;va_start(ap,fmt);int n=vsnprintf(o->txt,sizeof o->txt,fmt,ap);va_end(ap);return n;}
'''
post='''
int main(void) {
 wb_out o={{0}};cap=100;avail=40;
 assert(wb_ux0_budget(40,&o,true)==0 && strstr(o.txt,"available=40 required=40"));puts("PASS exact fit");
 assert(wb_ux0_budget(41,&o,true)==WB_E_LIMIT && strstr(o.txt,"ERR no-space"));puts("PASS one byte short");
 api=-1;assert(wb_ux0_budget(0,&o,true)==WB_E_IO && strstr(o.txt,"space-unavailable"));puts("PASS unknown api");
 api=0;cap=0;assert(wb_ux0_budget(0,&o,true)==WB_E_IO);cap=100;avail=101;assert(wb_ux0_budget(0,&o,true)==WB_E_IO);puts("PASS invalid counter");
 avail=5;assert(wb_ux0_budget(UINT64_MAX,&o,true)==WB_E_LIMIT);puts("PASS UINT64_MAX");
 return 0;
}
'''
with tempfile.TemporaryDirectory() as t:
 d=Path(t);c=d/'budget.c';c.write_text(pre+source[start:end]+post);exe=d/('budget.exe' if os.name=='nt' else 'budget');subprocess.run(['gcc','-Wall','-Wextra','-Werror',str(c),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
