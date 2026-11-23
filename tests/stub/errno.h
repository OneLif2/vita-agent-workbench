#ifndef WB_STUB_ERRNO_H
#define WB_STUB_ERRNO_H
/* The host already has a complete errno.h; pull it through so MinGW's
 * malloc.h and friends keep working. */
#include_next <errno.h>
#endif
