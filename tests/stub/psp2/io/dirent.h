#ifndef WB_STUB_PSP2_IO_DIRENT_H
#define WB_STUB_PSP2_IO_DIRENT_H
#include <psp2/io/stat.h>
typedef struct { SceIoStat d_stat; char d_name[256]; } SceIoDirent;
SceUID sceIoDopen(const char *dir);
int sceIoDread(SceUID fd, SceIoDirent *dir);
int sceIoDclose(SceUID fd);
#endif
