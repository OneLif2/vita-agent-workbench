#ifndef WB_STUB_PSP2_IO_STAT_H
#define WB_STUB_PSP2_IO_STAT_H
#include <psp2/types.h>
typedef struct { uint16_t year, month, day, hour, minute, second; uint32_t microsecond; } SceDateTime;
typedef struct {
    SceMode st_mode;
    unsigned int st_attr;
    SceOff st_size;
    SceDateTime st_ctime, st_atime, st_mtime;
} SceIoStat;
#define SCE_S_ISDIR(m) (((m) & 0xF000) == 0x1000)
#define SCE_S_ISREG(m) (((m) & 0xF000) == 0x2000)
int sceIoMkdir(const char *dir, SceMode mode);
int sceIoRmdir(const char *dir);
int sceIoRemove(const char *file);
int sceIoRename(const char *from, const char *to);
int sceIoGetstat(const char *file, SceIoStat *stat);
enum { SCE_SEEK_SET = 0, SCE_SEEK_CUR = 1, SCE_SEEK_END = 2 };
#endif
