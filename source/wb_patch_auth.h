#ifndef WB_PATCH_AUTH_H
#define WB_PATCH_AUTH_H
#include "wb_standing_message.h"
#include "wb_app_patch_recipe.h"
enum {WB_PATCH_MESSAGE_CAP=512};
/* The recipe SHA binds all allowed base and target member sizes/digests. The
 * app-approve and WBQ2 signature formats are deliberately not accepted here. */
static inline bool wb_patch_message(char dst[WB_PATCH_MESSAGE_CAP],const char *run,const char *path){
    static const char root[]="ux0:/VITA-POC/";
    if(!path||strncmp(path,root,sizeof root-1)||!wb_r1_hex(run,16,true,true))return false;
    const char *name=path+sizeof root-1;size_t n=strlen(name);
    if(n<5||n>=100||name[0]=='.'||strstr(name,"..")||strcmp(name+n-4,".bin")||
       strspn(name,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")!=n)return false;
    int k=snprintf(dst,WB_PATCH_MESSAGE_CAP,"WB-APP-PATCH-v1\nRUN %s\nTITLE %s\nTARGET %s\nRECIPE %s\nVPK %s\nPATH %s\n",
        run,WB_PATCH_TITLE,WB_PATCH_VERSION,WB_PATCH_RECIPE_SHA,WB_PATCH_VPK_SHA,path);
    return k>0 && k<WB_PATCH_MESSAGE_CAP;
}
#endif
