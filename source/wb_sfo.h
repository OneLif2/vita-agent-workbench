#ifndef WB_SFO_H
#define WB_SFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *data;
    size_t size;
    uint32_t key_off;
    uint32_t val_off;
    uint32_t count;
} wb_sfo;

int wb_sfo_parse(wb_sfo *s, const uint8_t *data, size_t size);
/* Validate the entire parsed index, not just the first requested fields. */
bool wb_sfo_unambiguous(const wb_sfo *s);
/* Copies a UTF-8 string field; returns WB_OK, WB_E_FORMAT when absent. */
int wb_sfo_get(const wb_sfo *s, const char *key, char *out, size_t cap);
int wb_sfo_get_u32(const wb_sfo *s, const char *key, uint32_t *out);

/* TITLE_ID shape used by the installer: exactly 9 chars, [A-Z0-9]. */
bool wb_titleid_ok(const char *titleid);

#endif
