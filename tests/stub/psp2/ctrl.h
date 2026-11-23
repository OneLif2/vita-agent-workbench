#ifndef WB_STUB_PSP2_CTRL_H
#define WB_STUB_PSP2_CTRL_H
#include <psp2/types.h>
typedef struct SceCtrlData {
    uint64_t timestamp;
    unsigned int buttons;
    unsigned char lx, ly, rx, ry;
    unsigned char reserved[16];
} SceCtrlData;
enum {
    SCE_CTRL_SELECT = 0x000001, SCE_CTRL_START = 0x000008,
    SCE_CTRL_UP = 0x000010, SCE_CTRL_RIGHT = 0x000020, SCE_CTRL_DOWN = 0x000040, SCE_CTRL_LEFT = 0x000080,
    SCE_CTRL_CROSS = 0x004000, SCE_CTRL_CIRCLE = 0x002000, SCE_CTRL_TRIANGLE = 0x001000, SCE_CTRL_SQUARE = 0x008000
};
int sceCtrlPeekBufferPositive(int port, SceCtrlData *pad, int count);
#endif
