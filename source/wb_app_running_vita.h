#ifndef WB_APP_RUNNING_VITA_H
#define WB_APP_RUNNING_VITA_H
/* Read-only AppMgr-started-app snapshot, NOT a kernel process list or reliable
 * foreground identity. ForShell APIs may deny ordinary homebrew at runtime. */
#include <psp2/appmgr.h>
#include <stdint.h>
#include <string.h>
#include "wb_cmd.h"
#include "wb_out.h"
#define WB_RUNNING_CAP 8
/* Published in the SceAppMgr error list (0x80802012); the pinned SDK header on
 * this build host predates the name, so carry the value explicitly. */
#ifndef SCE_APPMGR_ERROR_NOT_FOUND
#define SCE_APPMGR_ERROR_NOT_FOUND 0x80802012
#endif
/* A compiled title that no flow ever starts, used as the negative control. */
#define WB_RUNNING_CONTROL_TITLE "VSSH00001"
typedef struct {
    SceInt32 app_id; SceUID pid;
    char title_id[32], name[64];
    const char *issue; int rc;
} wb_running_row;
static bool wb_running_title(const char *s,size_t cap) {
    const char *end=memchr(s,0,cap);
    if(!end || end-s!=9)return false;
    for(unsigned i=0;i<9;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')))return false;
    return true;
}
static bool wb_running_name(const char *s,size_t cap) {
    const char *end=memchr(s,0,cap);if(!end||end==s)return false;
    for(const char *p=s;p<end;p++)if((unsigned char)*p<32||(unsigned char)*p>126||*p=='"'||*p=='\\')return false;
    return true;
}
static bool wb_running_ids(SceInt32 *ids,int n) {
    if(n<0||n>WB_RUNNING_CAP)return false;
    for(int i=0;i<n;i++){
        if(ids[i]<=0)return false;
        for(int j=i+1;j<n;j++)if(ids[i]==ids[j])return false;
    }
    for(int i=0;i<n;i++)for(int j=i+1;j<n;j++)if(ids[j]<ids[i]){SceInt32 t=ids[i];ids[i]=ids[j];ids[j]=t;}
    return true;
}
static int wb_running_error(wb_out*out,int*status,const char*why,int rc) {
    *status=1;
    return wb_out_printf(out,"ERR app-running INCONCLUSIVE %s rc=%d (0x%08X) foreground=unknown scope=appmgr-started-apps\n",why,rc,(unsigned)rc);
}
/* Only the published SceAppMgr error names; anything else stays unknown so a
 * bare rc is never re-labelled as a proven denial. */
static const char *wb_running_symbol(int rc) {
    switch((unsigned)rc){
    case (unsigned)SCE_APPMGR_ERROR_BUSY:return "BUSY";
    case (unsigned)SCE_APPMGR_ERROR_NOT_FOUND:return "NOT_FOUND";
    /* Published kernel error name only; it does not establish a permission cause. */
    case UINT32_C(0x80022005):return "KERNEL_INVALID_MEMORY_ACCESS";
    case (unsigned)SCE_APPMGR_ERROR_STATE:return "STATE";
    case (unsigned)SCE_APPMGR_ERROR_NULL_POINTER:return "NULL_POINTER";
    case (unsigned)SCE_APPMGR_ERROR_INVALID:return "INVALID";
    case (unsigned)SCE_APPMGR_ERROR_TOO_LONG_ARGV:return "TOO_LONG_ARGV";
    case (unsigned)SCE_APPMGR_ERROR_INVALID_SELF_PATH:return "INVALID_SELF_PATH";
    case (unsigned)SCE_APPMGR_ERROR_NOEXEC:return "NOEXEC";
    case (unsigned)SCE_APPMGR_ERROR_BGM_PORT_BUSY:return "BGM_PORT_BUSY";
    default:return "unknown";
    }
}
/* Read-only capability probe, entered only after the primary enumeration
 * failed. One extra list call per capacity and one known-title identity query:
 * no retry loop, no id scanning, no state change, and never presented as a
 * process list or as a foreground claim. Capacity 1 succeeding means
 * "PARTIAL, potentially truncated", not "the first entry is foreground". */
static int wb_running_diagnose(wb_out *out,int list_rc) {
    SceInt32 one[1]={0};
    const int rc1=sceAppMgrGetRunningAppIdListForShell(one,1);
    SceUID known=0;
    const int rcid=sceAppMgrGetIdByName(&known,WB_TITLE_ID);
    /* One write per line: the whole block no longer fits wb_out_printf's buffer. */
    int rc=0;
    rc|=wb_out_printf(out,"app-running probe=ForShell capacity=%d rc=%d (0x%08X) symbol=%s\n",
                      WB_RUNNING_CAP,list_rc,(unsigned)list_rc,wb_running_symbol(list_rc));
    rc|=wb_out_printf(out,"app-running probe=ForShell capacity=1 rc=%d (0x%08X) symbol=%s partial_capacity_capable=%s\n",
                      rc1,(unsigned)rc1,wb_running_symbol(rc1),rc1>=0&&rc1<=1?"yes":"unknown");
    rc|=wb_out_printf(out,"app-running probe=GetIdByName title=%s rc=%d (0x%08X) pid=%d identity=%s\n",
                      WB_TITLE_ID,rcid,(unsigned)rcid,(int)known,rcid==0&&known>0?"observed":"unknown");
    rc|=wb_out_puts(out,"app-running probe=GetAppInfo state=not-probed reason=abi-unverified\n");
    rc|=wb_out_puts(out,"app-running probe=GetStatusByName state=not-probed reason=abi-unverified\n");
    rc|=wb_out_puts(out,"app-running probe=GetPidListForShell state=not-probed reason=abi-unverified\n");
    rc|=wb_out_puts(out,"app-running note=read-only-capability-probe; one-call-per-form; no-retry; no-id-scan; "
                         "not-a-process-list; no-foreground-claim; is_running-is-per-title-not-foreground\n");
    return rc;
}
/* Shared by single-title and approved-table queries. Only NOT_FOUND proves
 * not-started; a bad PID with rc=0 is an invalid result, never absence. */
static const char *wb_running_query_state(int rc,SceUID pid) {
    if(rc==0 && pid>0)return "started";
    if((unsigned)rc==(unsigned)SCE_APPMGR_ERROR_NOT_FOUND)return "not-started";
    return "unknown";
}
/* Shared admission for the main table route and this module. No API is called
 * until all paired-owner PTY and descriptor checks have passed. */
static const char *wb_running_admission(const wb_cmd *cmd) {
    if(!wb_standing_owner_pty()||!wb_ssh_connected(&g_ssh))return "no-paired-pty";
    if(cmd->kind!=WB_CMD_TERM_APP_RUNNING||(cmd->argc!=0&&cmd->argc!=1)||cmd->force||cmd->no_reload||cmd->keep_stage||
       cmd->install_after||cmd->no_period||cmd->promote_now||cmd->any_title||cmd->sha256[0])
        return "usage: ps | app running [TITLEID]";
    return NULL;
}
/* One exact title, one call. `started` means AppMgr resolved the name to a
 * process; it says nothing about which app has focus. */
static int wb_running_title_query(const wb_cmd *cmd,wb_out *out,int *status) {
    char title[10];
    memcpy(title,cmd->argv[0],9);title[9]=0;
    SceUID pid=0;
    const int rc=sceAppMgrGetIdByName(&pid,title);
    const char *state=wb_running_query_state(rc,pid);
    *status = !strcmp(state,"started") ? 0 : 1;
    if(!strcmp(state,"started"))
        return wb_out_printf(out,"OK app-running title=%s state=started pid=%d source=GetIdByName\n",
                             title,(int)pid);
    if(rc==0)
        return wb_out_printf(out,"ERR app-running title=%s state=unknown pid=%d rc=0 (0x00000000) symbol=INVALID_RESULT source=GetIdByName\n",
                             title,(int)pid);
    if((unsigned)rc==(unsigned)SCE_APPMGR_ERROR_NOT_FOUND)
        return wb_out_printf(out,"ERR app-running title=%s state=not-started rc=%d (0x%08X) symbol=NOT_FOUND source=GetIdByName\n",
                             title,rc,(unsigned)rc);
    return wb_out_printf(out,"ERR app-running title=%s state=unknown rc=%d (0x%08X) symbol=%s source=GetIdByName\n",
                         title,rc,(unsigned)rc,wb_running_symbol(rc));
}
static void wb_running_issue(wb_running_row*r,const char*why,int rc) {
    if(!r->issue){r->issue=why;r->rc=rc;}
}
static int wb_app_running_command(const wb_cmd*cmd,wb_out*out,int*status) {
    *status=1;
    const char *why=wb_running_admission(cmd);
    if(why)return wb_running_error(out,status,why,0);
    if(cmd->argc==1){
        if(!wb_running_title(cmd->argv[0],sizeof cmd->argv[0]))
            return wb_running_error(out,status,"needs a 9-character title id",0);
        return wb_running_title_query(cmd,out,status);
    }
    SceInt32 first[WB_RUNNING_CAP]={0},second[WB_RUNNING_CAP]={0};
    int n=sceAppMgrGetRunningAppIdListForShell(first,WB_RUNNING_CAP);
    if(n<0){
        if(wb_running_diagnose(out,n)<0)return -1;
        return wb_running_error(out,status,"unsupported-or-denied list-first",n);
    }
    if(!wb_running_ids(first,n))return wb_running_error(out,status,"invalid-or-overflow list-first",n);
    wb_running_row rows[WB_RUNNING_CAP];memset(rows,0,sizeof rows);bool partial=n==WB_RUNNING_CAP;
    for(int i=0;i<n;i++){
        wb_running_row *r=&rows[i];r->app_id=first[i];
        r->pid=sceAppMgrGetProcessIdByAppIdForShell(r->app_id);
        if(r->pid<=0){wb_running_issue(r,"pid-unavailable",r->pid);r->pid=0;partial=true;continue;}
        int rc=sceAppMgrGetNameById(r->pid,r->title_id);
        if(rc!=0||!wb_running_title(r->title_id,sizeof r->title_id)){
            wb_running_issue(r,rc?"title-query-failed":"title-invalid",rc);r->title_id[0]=0;partial=true;
        }
        rc=sceAppMgrAppParamGetString(r->pid,10,r->name,sizeof r->name);
        if(rc!=0||!wb_running_name(r->name,sizeof r->name)){
            wb_running_issue(r,rc?"name-query-failed":"name-unavailable-nonascii-or-invalid",rc);r->name[0]=0;partial=true;
        }
    }
    int m=sceAppMgrGetRunningAppIdListForShell(second,WB_RUNNING_CAP);
    if(m<0)return wb_running_error(out,status,"unsupported-or-denied list-second",m);
    if(!wb_running_ids(second,m))return wb_running_error(out,status,"invalid-or-overflow list-second",m);
    if(m!=n||memcmp(first,second,(size_t)n*sizeof *first))return wb_running_error(out,status,"changing-snapshot",m);
    /* Same app IDs alone are not enough: IDs or PIDs can be recycled while
     * text was queried. Recheck each handle/title and suppress stale values. */
    for(int i=0;i<n;i++){
        wb_running_row *r=&rows[i];SceUID pid=sceAppMgrGetProcessIdByAppIdForShell(r->app_id);
        if(pid<=0||!r->pid||pid!=r->pid){
            wb_running_issue(r,"pid-changed-or-disappeared",pid);r->pid=0;r->title_id[0]=r->name[0]=0;partial=true;continue;
        }
        char title[32]={0};int rc=sceAppMgrGetNameById(pid,title);
        if(rc!=0||!wb_running_title(title,sizeof title)||!r->title_id[0]||strcmp(title,r->title_id)){
            wb_running_issue(r,"title-changed-or-unavailable",rc);r->title_id[0]=r->name[0]=0;partial=true;
        }
    }
    *status=partial?1:0;
    if(wb_out_printf(out,"app-running state=%s run=%.16s count=%d capacity=%d potentially_truncated=%s foreground=unknown scope=appmgr-started-apps\n",
        partial?"INCONCLUSIVE":"TWO_SAMPLE_SNAPSHOT",a.run_hex,n,WB_RUNNING_CAP,n==WB_RUNNING_CAP?"yes":"no")<0)return -1;
    for(int i=0;i<n;i++){
        const wb_running_row *r=&rows[i];
        if(wb_out_printf(out,"app_id=%d pid=%d title_id=%s name_sfo10=\"%s\" field_state=%s step=%s rc=%d (0x%08X)\n",
            (int)r->app_id,(int)r->pid,r->title_id[0]?r->title_id:"unknown",r->name[0]?r->name:"unknown",
            r->issue?"unknown":"observed",r->issue?r->issue:"none",r->rc,(unsigned)r->rc)<0)return -1;
    }
    return wb_out_puts(out,"app-running note=bounded-two-sample-not-atomic; not-all-kernel-processes; no-foreground-claim\n");
}
#endif
