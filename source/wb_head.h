#ifndef WB_HEAD_H
#define WB_HEAD_H

#include <stddef.h>
#include <stdint.h>

/* head.bin is the fake PKG header the Vita promoter expects inside a package
 * directory. Layout and HMAC derivation follow VitaShell's makeHeadBin(). */
#define WB_HEAD_SIZE 1072u

int wb_head_build(uint8_t *out, size_t cap, const char *titleid, const char *contentid);

#endif
