#ifndef WB_CRC32_H
#define WB_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t wb_crc32_update(uint32_t crc, const void *data, size_t len);
uint32_t wb_crc32(const void *data, size_t len);

#endif
