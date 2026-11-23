#ifndef WB_APP_REMOVE_POLICY_H
#define WB_APP_REMOVE_POLICY_H
#include <string.h>
/* Fixed-format installed title IDs only. No paths, aliases, system namespace,
 * this lifecycle pair, or recovery/boot tooling. The native layer repeats
 * this check even when a caller has passed the interactive parser. */
static inline int wb_remove_id(const char *s){
    if(!s||strlen(s)!=9)return 0;
    for(int i=0;i<9;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')))return 0;
    return strncmp(s,"NPX",3)&&strncmp(s,"WBCZ",4)&&strcmp(s,"INAP00018")&&strcmp(s,"INAP00019")&&
           strcmp(s,"VITASHELL")&&strcmp(s,"MLCL00001")&&strcmp(s,"SKGD3PL0Y")&&strcmp(s,"PCSG90096")&&strcmp(s,"VSSH00001");
}
static inline int wb_remove_hex(const char *s){
    if(!s||strlen(s)!=64)return 0;
    for(int i=0;i<64;i++)if(!((s[i]>='a'&&s[i]<='f')||(s[i]>='0'&&s[i]<='9')))return 0;
    return 1;
}
#endif
