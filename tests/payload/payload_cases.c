/* Host-only regression fixture: no network, directory or hardware access. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "payload-under-test.c"

static const char *const dir = "ux0:/VITA-POC";
static char text[8192];
static size_t used;
static int index_, closes, nonzero_on_entry, forbidden, failures, total;
static int read_fails_after, close_result, no_entries, fail_write, temperature;

static int sink(void *unused, const char *s, size_t n) {
    (void)unused;
    if (fail_write || n >= sizeof(text)-used) return -1;
    memcpy(text+used,s,n); used+=n; text[used]=0;
    return 0;
}
static wb_out output={NULL,sink};

static void reset_state(void) {
    used=0; text[0]=0; index_=closes=nonzero_on_entry=forbidden=0;
    read_fails_after=-1; close_result=0; no_entries=fail_write=0;
}

SceUID sceIoDopen(const char *p) {return strcmp(p,dir)==0 ? 42 : -1;}
int sceIoDread(SceUID fd, SceIoDirent *ent) {
    static const char *const names[]={".","..","docs","notes.txt"};
    if(fd!=42 || !ent) {++forbidden; return -1;}
    const unsigned char *bytes=(const unsigned char *)ent;
    for(size_t i=0;i<sizeof(*ent);i++) if(bytes[i]!=0) {nonzero_on_entry++;break;}
    if(index_==read_fails_after) return -5;
    if(no_entries || index_==4) return 0;
    /* Include padding in subsequent zero-initialization checks. This is a
     * deterministic model of the API, not a device ABI layout assertion. */
    memset(ent, 0x6c, sizeof(*ent));
    snprintf(ent->d_name,sizeof(ent->d_name),"%s",names[index_]);
    ent->d_stat.st_mode = index_==3 ? 0x2000 : 0x1000;
    ent->d_stat.st_size = index_==3 ? 37 : 0;
    ++index_; return 1;
}
int sceIoDclose(SceUID fd){ if(fd!=42) ++forbidden; ++closes; return close_result; }
uint64_t sceKernelGetProcessTimeWide(void){return 512000;}
int scePowerGetBatteryTemp(void){return temperature;}
int scePowerGetBatteryLifePercent(void){return 77;}
int scePowerIsBatteryCharging(void){return 0;}
int scePowerIsPowerOnline(void){return 1;}
/* Other linked payload features are never exercised. */
SceUID sceIoOpen(const char *p,int f,SceMode m){(void)p;(void)f;(void)m;++forbidden;return -1;}
int sceIoWrite(SceUID fd,const void *p,SceSize n){(void)p;(void)n;(void)fd;++forbidden;return -1;}
int sceIoClose(SceUID fd){(void)fd;++forbidden;return -1;}
int sceIoGetstat(const char *p,SceIoStat *s){(void)p;(void)s;++forbidden;return -1;}
int sceIoMkdir(const char *p,SceMode m){(void)p;(void)m;++forbidden;return -1;}
int sceIoRmdir(const char *p){(void)p;++forbidden;return -1;}
int sceIoRemove(const char *p){(void)p;++forbidden;return -1;}
int sceIoRename(const char *p,const char *q){(void)p;(void)q;++forbidden;return -1;}

static void result(const char *label,int ok,int rc) {
    ok = ok && !forbidden; ++total;
    printf("%s %s rc=%d closes=%d dirty=%d",ok?"PASS":"FAIL",label,rc,closes,nonzero_on_entry);
    if(!ok){ ++failures; printf(" output=[%s]",text); }
    puts("");
}
static int list(void) { return cmd_ls(&output, dir); }
static void run_ls(void) {
    for(int i=0;i<2;i++){
        reset_state();int rc=list();
        result(i?"repeat-directory":"mixed-entries",rc==0 && strcmp(text,"D docs\nF notes.txt 37\n")==0 &&
               index_==4 && closes==1 && !nonzero_on_entry,rc);
    }
    reset_state();no_entries=1;int rc=list();
    result("empty-directory",rc==0 && !text[0] && closes==1 && !nonzero_on_entry,rc);
    reset_state();read_fails_after=0;rc=list();
    result("read-failed-before-first-entry",rc<0 && strstr(text,"ERR read-failed\n") && closes==1 && !nonzero_on_entry,rc);
    reset_state();read_fails_after=3;rc=list();
    result("read-failed-after-directory-entry",rc<0 && strstr(text,"D docs\n") && strstr(text,"ERR read-failed\n") &&
           closes==1 && !nonzero_on_entry,rc);
    reset_state();close_result=-9;rc=list();
    result("close-failed",rc<0 && strstr(text,"ERR close-failed\n") && closes==1 && !nonzero_on_entry,rc);
    reset_state();fail_write=1;rc=list();
    result("output-failed",rc<0 && closes==1 && !nonzero_on_entry,rc);
}
static void run_temp(void){
    struct item{int raw;const char *value;} cases[]={
        {3009,"30"},{1001,"10"},{1000,"10"},{999,"9"},{100,"1"},{99,"0"},{0,"0"},
        {-1,"unavailable"},{INT_MIN,"unavailable"}
    };
    for(size_t i=0;i<sizeof(cases)/sizeof(*cases);i++){
        reset_state();temperature=cases[i].raw;int rc=cmd_sys(&output);
        char want[80],label[80];
        snprintf(want,sizeof(want),"payload temp_c=%s\n",cases[i].value);
        snprintf(label,sizeof(label),"temperature(raw=%d expected=%s)",temperature,cases[i].value);
        result(label,rc==0 && strstr(text,want) && strstr(text,"payload online=1\n"),rc);
    }
}
int main(void){ run_ls();run_temp();printf("RESULT %d/%d passed\n",total-failures,total);return failures?1:0; }
