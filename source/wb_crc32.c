#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("O3")
#endif
#include "wb_crc32.h"

static const uint32_t T[16] = {
    0x00000000u,0x1db71064u,0x3b6e20c8u,0x26d930acu,
    0x76dc4190u,0x6b6b51f4u,0x4db26158u,0x5005713cu,
    0xedb88320u,0xf00f9344u,0xd6d6a3e8u,0xcb61b38cu,
    0x9b64c2b0u,0x86d3d2d4u,0xa00ae278u,0xbdbdf21cu
};

uint32_t wb_crc32_update(uint32_t crc, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        crc = (crc >> 4) ^ T[crc & 0xfu];
        crc = (crc >> 4) ^ T[crc & 0xfu];
    }
    return ~crc;
}

uint32_t wb_crc32(const void *data, size_t len) {
    return wb_crc32_update(0, data, len);
}
