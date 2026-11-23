#include "wb_sfo.h"
#include "wb_err.h"

#include <string.h>

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

int wb_sfo_parse(wb_sfo *s, const uint8_t *data, size_t size) {
    if (!s || !data || size < 20) return WB_E_FORMAT;
    if (!(data[0] == 0x00 && data[1] == 'P' && data[2] == 'S' && data[3] == 'F')) return WB_E_FORMAT;
    memset(s, 0, sizeof *s);
    s->data = data;
    s->size = size;
    s->key_off = le32(data + 8);
    s->val_off = le32(data + 12);
    s->count   = le32(data + 16);
    if (s->count == 0 || s->count > 64) return WB_E_FORMAT;
    const size_t index_end = 20u + (size_t)s->count * 16u;
    if (index_end > size || s->key_off < index_end ||
        s->key_off >= s->val_off || s->val_off > size)
        return WB_E_FORMAT;
    return WB_OK;
}

static int entry(const wb_sfo *s, uint32_t i, const char **key, uint16_t *fmt,
                 uint32_t *len, uint32_t *dataofs) {
    const size_t off = 20u + (size_t)i * 16u;
    if (off + 16u > s->size) return WB_E_FORMAT;
    const uint8_t *p = s->data + off;
    const uint16_t nameofs = le16(p);
    *fmt = le16(p + 2);
    *len = le32(p + 4);
    *dataofs = le32(p + 12);
    if (nameofs >= s->val_off - s->key_off) return WB_E_FORMAT;
    const size_t koff = (size_t)s->key_off + nameofs;
    if (!memchr(s->data + koff, 0, s->val_off - koff)) return WB_E_FORMAT;
    *key = (const char *)(s->data + koff);
    const size_t available = s->size - s->val_off;
    if (*dataofs > available || *len > available - *dataofs) return WB_E_FORMAT;
    return WB_OK;
}

bool wb_sfo_unambiguous(const wb_sfo *s) {
    const char *keys[64];
    uint32_t starts[64], ends[64];
    if (!s || !s->data || !s->count || s->count > 64 || le32(s->data + 4) != 0x00000101u)
        return false;
    const size_t value_bytes = s->size - s->val_off;
    for (uint32_t i = 0; i < s->count; ++i) {
        uint16_t fmt;
        uint32_t len, off;
        if (entry(s, i, &keys[i], &fmt, &len, &off) != WB_OK || !*keys[i]) return false;
        const uint32_t cap = le32(s->data + 20u + (size_t)i * 16u + 8u);
        if (len > cap || off > value_bytes || cap > value_bytes - off) return false;
        const uint8_t *v = s->data + (size_t)s->val_off + off;
        if (fmt == 0x0204u) {
            if (!len || memchr(v, 0, len) != v + len - 1u) return false;
        } else if (fmt == 0x0404u) {
            if (len != 4u) return false;
        } else if (fmt != 0x0004u) return false;
        starts[i] = off;
        ends[i] = off + cap;
        for (uint32_t j = 0; j < i; ++j)
            if (!strcmp(keys[i], keys[j]) ||
                (starts[i] < ends[j] && starts[j] < ends[i])) return false;
    }
    return true;
}

int wb_sfo_get(const wb_sfo *s, const char *key, char *out, size_t cap) {
    if (!s || !key || !out || cap == 0) return WB_E_ARG;
    for (uint32_t i = 0; i < s->count; i++) {
        const char *k;
        uint16_t fmt;
        uint32_t len, dataofs;
        if (entry(s, i, &k, &fmt, &len, &dataofs) != WB_OK) return WB_E_FORMAT;
        if (strcmp(k, key) != 0 || fmt != 0x0204u) continue;
        size_t n = 0;
        const uint8_t *v = s->data + ((size_t)s->val_off + dataofs);
        for (; n < len && v[n]; n++) {}
        if (n == len) return WB_E_FORMAT;
        if (n >= cap) return WB_E_LIMIT;
        memcpy(out, v, n);
        out[n] = 0;
        return WB_OK;
    }
    return WB_E_FORMAT;
}

int wb_sfo_get_u32(const wb_sfo *s, const char *key, uint32_t *out) {
    if (!s || !key || !out) return WB_E_ARG;
    for (uint32_t i = 0; i < s->count; i++) {
        const char *k;
        uint16_t fmt;
        uint32_t len, dataofs;
        if (entry(s, i, &k, &fmt, &len, &dataofs) != WB_OK) return WB_E_FORMAT;
        if (strcmp(k, key) != 0 || fmt != 0x0404u || len != 4) continue;
        *out = le32(s->data + ((size_t)s->val_off + dataofs));
        return WB_OK;
    }
    return WB_E_FORMAT;
}

bool wb_titleid_ok(const char *titleid) {
    if (!titleid || strlen(titleid) != 9) return false;
    for (const char *p = titleid; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9'))) return false;
    }
    return true;
}
