/* Inspect the same generated C tables consumed by the Vita adapter (host only). */
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "wb_sha256.h"
#include "wb_app_patch_recipe.h"
int main(void){
    printf("recipe %s %s %s %" PRIu64 " %s\n",WB_PATCH_TITLE,WB_PATCH_VERSION,WB_PATCH_RECIPE_SHA,WB_PATCH_VPK_BYTES,WB_PATCH_VPK_SHA);
    for(unsigned i=0;i<=WB_PATCH_BASE_COUNT;i++){
        int target=i==WB_PATCH_BASE_COUNT;
        const char *v=target?WB_PATCH_VERSION:wb_patch_base_versions[i];
        for(unsigned j=0;j<WB_PATCH_FILE_COUNT;j++){
            const wb_patch_file *r=target?&wb_patch_target[j]:&wb_patch_bases[i][j];
            int allowed=target&&(!strcmp(r->path,"sce_sys/param.sfo")||!strcmp(r->path,"build-manifest.json"));
            if(allowed!=(r->embedded!=NULL))return 1;
            if(allowed){
                uint8_t sum[32];char hex[65];wb_sha256 h;
                wb_sha256_init(&h);wb_sha256_update(&h,r->embedded,(size_t)r->bytes);
                wb_sha256_final(&h,sum);wb_sha_hex(sum,32,hex);if(strcmp(hex,r->sha))return 2;
            }
            printf("%s %s %" PRIu64 " %s %s\n",v,r->path,r->bytes,r->sha,allowed?"embedded":"external");
        }
    }
    return 0;
}
