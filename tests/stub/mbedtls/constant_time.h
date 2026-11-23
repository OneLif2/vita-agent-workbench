#ifndef WB_STUB_MBEDTLS_CONSTANT_TIME_H
#define WB_STUB_MBEDTLS_CONSTANT_TIME_H
#include <stddef.h>
int mbedtls_ct_memcmp(const void *a, const void *b, size_t n);
#endif
