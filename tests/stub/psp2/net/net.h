#ifndef WB_STUB_PSP2_NET_NET_H
#define WB_STUB_PSP2_NET_NET_H
#include <psp2/types.h>
typedef struct SceNetInitParam {
    void *memory;
    int size;
    int flags;
} SceNetInitParam;
int sceNetInit(SceNetInitParam *param);
int sceNetTerm(void);
#endif
