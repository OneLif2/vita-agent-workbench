#ifndef WB_VITA_PHOTO_H
#define WB_VITA_PHOTO_H

#include <stddef.h>

/* Limit the single immutable, encoded JPEG/PNG buffer and preclude SceSize
 * truncation. The command gate checks source, type, size and digest first. */
#define WB_VITA_PHOTO_MAX_BYTES (8u * 1024u * 1024u)

/* Called only by the serialized command dispatcher. A nonnegative result
 * means the platform accepted an import; NOT that a human saw the image.
 * On error preserve the native result. An unload error is diagnostic only:
 * never retry a possibly committed import on the strength of cleanup_rc. */
int wb_vita_photo_export(const void *verified_data, size_t image_len,
                         int *cleanup_rc);

#endif
