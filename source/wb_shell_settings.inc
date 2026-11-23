/* LiveArea layout belongs to SceShell. This PTY action reads two existing
 * Workbench services with constant arguments. It cannot move, hide or delete
 * a bubble; returning an instruction does NOT confirm a layout change. */
#define WB_SETTINGS_HELP "settings updater-folder: check pending updates and updater eboot; show owner steps. Never edits LiveArea.\n"
#define WBSH_UPDATER_EBOOT "ux0:/app/INAP00019/eboot.bin"
typedef struct {char txt[192];size_t n;bool bad;} wbsh_reply;
static int wbsh_collect(void *p,const char *bytes,size_t n){
    wbsh_reply *r=p;
    if(n > sizeof r->txt-1-r->n || memchr(bytes,0,n)){r->bad=true;return -1;}
    memcpy(r->txt+r->n,bytes,n);r->n+=n;r->txt[r->n]=0;return 0;
}
static bool wbsh_fixed(const wb_shell_ops *ops,const char *query,wbsh_reply *r){
    wb_cmd c;wb_out sink={r,wbsh_collect};memset(r,0,sizeof *r);
    return wb_cmd_parse(query,strlen(query),&c) && core_raw(ops,&c,&sink)==0 && !r->bad;
}
static bool wbsh_updater_file(const char *s){
    const char *pref="F " WBSH_UPDATER_EBOOT " ";
    const size_t n=strlen(pref);
    if(strncmp(s,pref,n)!=0 || s[n]<'1'||s[n]>'9')return false;
    size_t count=strspn(s+n,"0123456789");
    return count<=10 && !strcmp(s+n+count,"\n");
}
static int wbsh_settings(const wb_shell_ops *ops,int n,char **v,wb_out *out){
    if(n==1)return say(out,WB_SETTINGS_HELP);
    if(n!=2 || !eq(v[1],"updater-folder"))return say(out,"ERR usage: settings updater-folder\n");
    wbsh_reply r;
    if(!wbsh_fixed(ops,"pending",&r) || strcmp(r.txt,"pending-core: no\n")){
        return say(out,"WAIT title=INAP00019 reason=update-queued-or-unknown layout=unchanged\n"
                       "Leave Workbench in front. Do not edit Home during an update.\n");
    }
    if(!wbsh_fixed(ops,"ext stat " WBSH_UPDATER_EBOOT,&r) || !wbsh_updater_file(r.txt)){
        return say(out,"UNVERIFIED title=INAP00019 reason=updater-file-unconfirmed layout=unchanged\n");
    }
    return say(out,
        "NEEDS_OWNER title=INAP00019 updater-file=present layout=unverified\n"
        "No change made. When no update is in progress, touch and hold the Vita Home screen.\n"
        "Select Workbench Updater > Create Folder; name it WB Tools (or your preferred name).\n"
        "If the folder exists, drag the updater into it. If already inside, leave it there.\n"
        "Do not select Delete. Open the folder to verify the bubble is inside.\n");
}
