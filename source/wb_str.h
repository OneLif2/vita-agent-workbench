#ifndef WB_STR_H
#define WB_STR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Strict unsigned parse: digits only, no sign, no whitespace, overflow fails. */
bool wb_parse_u64(const char *s, uint64_t *out);

/* Strict hex decode; the input must be an even number of hex digits that fits
 * in cap. Returns the decoded byte count or -1. */
int wb_hex_decode(const char *hex, uint8_t *out, size_t cap);

/* Dotted numeric version compare ("01.10" > "01.09"). 1..4 components, each
 * 1..4 digits. Returns -1/0/1, or 0x7fffffff when either side does not parse. */
int wb_ver_cmp(const char *a, const char *b);

/* Copy with NUL termination; returns strlen(out). */
size_t wb_strcpy(char *dst, size_t cap, const char *src);

/* Case insensitive compare of ASCII. */
int wb_icmp(const char *a, const char *b);

#endif
