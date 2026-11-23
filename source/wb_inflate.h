#ifndef WB_INFLATE_H
#define WB_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/* Raw DEFLATE (RFC 1951) decoder, no zlib dependency.
 * out/outcap must describe the whole destination buffer. On WB_OK *outlen is
 * the decoded size. Returns WB_OK, WB_E_FORMAT, WB_E_LIMIT (destination too
 * small) or WB_E_PARTIAL (input truncated). */
int wb_inflate_raw(uint8_t *out, size_t outcap, size_t *outlen,
                   const uint8_t *in, size_t inlen);

#endif
