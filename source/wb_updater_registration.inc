/* Read-only LSDB query; share exactly the physically calibrated positive and
 * negative controls used for managed app inspection, not a guessed rc==0. */
int wb_vita_updater_registered(int *registered,int *detail) {
    if(!registered || !detail)return WB_E_ARG;
    *registered=-1; *detail=0;
    int rc=WB_E_IO, rv, disk, answer=-1;
    bool paf=false,mod=false,init=false;
    rv=load_paf(); if(rv<0)goto done; paf=true;
    rv=sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
    if(rv<0)goto done;
    mod=true;
    rv=scePromoterUtilityInit(); if(rv<0)goto done; init=true;
    /* If the platform state isn't idle, don't base an install decision on a
     * snapshot in the middle of somebody else's promoter work. */
    int state=-1; rv=scePromoterUtilityGetState(&state);
    if(rv<0)goto done;
    if(state!=0) { rc=WB_E_BUSY; rv=state; goto done; }
    disk=wbu_disk("ux0:/app/" WB_TITLE_ID,true,-1);
    if(disk!=1) { rc=disk<0?WB_E_IO:WB_E_STATE; rv=disk; goto done; }
    disk=wbu_disk("ux0:/app/" WBU_ABS_ID,true,-1);
    if(disk!=0) { rc=disk<0?WB_E_IO:WB_E_STATE; rv=disk; goto done; }
    wbu_query hit=wbu_q(WB_TITLE_ID),miss=wbu_q(WBU_ABS_ID);
    if(!wbu_missing_signature(hit,miss)) {
        rv=hit.rc!=0?hit.rc:miss.rc; rc=WB_E_STATE; goto done;
    }
    wbu_query q=wbu_q(WB_UPDATER_TITLE_ID);
    if(wbu_equal(q,miss))answer=0;
    else if(miss.rc<0 ? (q.rc==0 && (q.value>=0||q.value==INT_MIN)) : wbu_equal(q,hit))answer=1;
    else { rv=q.rc!=0?q.rc:q.value; rc=q.rc<0?WB_E_IO:WB_E_STATE; goto done; }
    rc=WB_OK; rv=0;
done:
    *detail=rv;
    if(init && (rv=scePromoterUtilityExit())<0 && rc==WB_OK) { *detail=rv; rc=WB_E_IO; }
    if(mod && (rv=sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL))<0 && rc==WB_OK) { *detail=rv; rc=WB_E_IO; }
    if(paf && (rv=unload_paf())<0 && rc==WB_OK) { *detail=rv; rc=WB_E_IO; }
    if(rc==WB_OK)*registered=answer;
    return rc;
}
