#include "wb_head.h"
#include "wb_err.h"
#include "wb_sha1.h"

#include <stdio.h>
#include <string.h>

#include "wb_head_template.inc"

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* VitaShell's pkg header HMAC: a domain separated SHA-1, truncated to 16. */
static void fpkg_hmac(const uint8_t *data, unsigned len, uint8_t hmac[16]) {
    wb_sha1 ctx;
    uint8_t sha1[20];
    uint8_t buf[64];

    wb_sha1_init(&ctx);
    wb_sha1_update(&ctx, data, len);
    wb_sha1_final(&ctx, sha1);

    memset(buf, 0, sizeof buf);
    memcpy(&buf[0], &sha1[4], 8);
    memcpy(&buf[8], &sha1[4], 8);
    memcpy(&buf[16], &sha1[12], 4);
    buf[20] = sha1[16];
    buf[21] = sha1[1];
    buf[22] = sha1[2];
    buf[23] = sha1[3];
    memcpy(&buf[24], &buf[16], 8);

    wb_sha1_init(&ctx);
    wb_sha1_update(&ctx, buf, sizeof buf);
    wb_sha1_final(&ctx, sha1);
    memcpy(hmac, sha1, 16);
}

int wb_head_build(uint8_t *out, size_t cap, const char *titleid, const char *contentid) {
    if (!out || cap < WB_HEAD_SIZE || !titleid) return WB_E_ARG;
    memcpy(out, wb_head_template, WB_HEAD_SIZE);

    char full_title_id[64];
    const int n = snprintf(full_title_id, sizeof full_title_id,
                           "EP9000-%s_00-0000000000000000", titleid);
    if (n <= 0 || (size_t)n >= sizeof full_title_id) return WB_E_ARG;

    const char *id = (contentid && *contentid) ? contentid : full_title_id;
    if (strlen(id) >= 48) return WB_E_ARG;
    memset(&out[0x30], 0, 48);
    memcpy(&out[0x30], id, strlen(id));

    uint8_t hmac[16];
    unsigned len = be32(&out[0xD0]);
    if (len >= WB_HEAD_SIZE) return WB_E_FORMAT;
    fpkg_hmac(&out[0], len, hmac);
    memcpy(&out[len], hmac, 16);

    const uint32_t off = be32(&out[0x08]);
    len = be32(&out[0x10]);
    const uint32_t out_off = be32(&out[0xD4]);
    if (off + len > WB_HEAD_SIZE || out_off + 16u > WB_HEAD_SIZE || len < 64u) return WB_E_FORMAT;
    fpkg_hmac(&out[off], len - 64u, hmac);
    memcpy(&out[out_off], hmac, 16);

    len = be32(&out[0xE8]);
    if (len > WB_HEAD_SIZE - 16u) return WB_E_FORMAT;
    fpkg_hmac(&out[0], len, hmac);
    memcpy(&out[len], hmac, 16);
    return WB_OK;
}
