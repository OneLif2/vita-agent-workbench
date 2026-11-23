#ifndef WB_STUB_PSP2_NET_NETCTL_H
#define WB_STUB_PSP2_NET_NETCTL_H
#include <psp2/types.h>
typedef struct SceNetCtlInfo {
    char ip_address[16];
    char netmask[16];
    char gateway[16];
} SceNetCtlInfo;
enum { SCE_NETCTL_STATE_CONNECTED = 2, SCE_NETCTL_INFO_GET_IP_ADDRESS = 1, SCE_NETCTL_INFO_GET_NETMASK = 5 };
int sceNetCtlInit(void);
int sceNetCtlTerm(void);
int sceNetCtlInetGetState(int *state);
int sceNetCtlInetGetInfo(int code, SceNetCtlInfo *info);
#endif
